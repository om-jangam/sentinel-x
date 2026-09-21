"""Sliding event-time windows for threshold rules: Redis in production, in memory for dev and tests."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from typing import cast

from redis.asyncio import Redis

from app.modules.detection.domain.ports import WindowEntry

# Entries older than twice the window before the newest one can never be counted again.
_RETENTION_WINDOWS = 2


class InMemoryWindowStore:
    """Single-process only: state is lost on restart and not shared between workers."""

    def __init__(self, *, max_keys: int = 10_000) -> None:
        self._windows: OrderedDict[str, dict[str, WindowEntry]] = OrderedDict()
        self._fired: dict[str, int] = {}
        self._max_keys = max_keys

    async def add(self, key: str, entry: WindowEntry, *, window_ms: int) -> list[WindowEntry]:
        window = self._windows.setdefault(key, {})
        self._windows.move_to_end(key)
        window.setdefault(entry.event_uid, entry)
        horizon = max(e.at_ms for e in window.values()) - _RETENTION_WINDOWS * window_ms
        for uid in [uid for uid, e in window.items() if e.at_ms < horizon]:
            del window[uid]
        while len(self._windows) > self._max_keys:
            evicted, _ = self._windows.popitem(last=False)
            self._fired.pop(evicted, None)
        return [e for e in window.values() if entry.at_ms - window_ms <= e.at_ms <= entry.at_ms]

    async def last_fired(self, key: str) -> int | None:
        return self._fired.get(key)

    async def mark_fired(self, key: str, at_ms: int, *, window_ms: int) -> None:
        self._fired[key] = max(at_ms, self._fired.get(key, at_ms))


class RedisWindowStore:
    """One sorted set per group (member = event, score = event time). Keys are hashed: groups hold IPs and users."""

    def __init__(self, redis: Redis, *, prefix: str = "sx:det:") -> None:
        self._redis = redis
        self._prefix = prefix

    def _keys(self, key: str) -> tuple[str, str]:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{self._prefix}win:{digest}", f"{self._prefix}fired:{digest}"

    async def add(self, key: str, entry: WindowEntry, *, window_ms: int) -> list[WindowEntry]:
        window_key, _ = self._keys(key)
        member = json.dumps([entry.event_uid, entry.value], separators=(",", ":"))
        ttl_ms = max(_RETENTION_WINDOWS * window_ms, 60_000)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zadd(window_key, {member: entry.at_ms}, nx=True)
            pipe.zremrangebyscore(window_key, "-inf", f"({entry.at_ms - _RETENTION_WINDOWS * window_ms}")
            pipe.zrangebyscore(window_key, entry.at_ms - window_ms, entry.at_ms, withscores=True)
            pipe.pexpire(window_key, ttl_ms)
            results = await pipe.execute()
        rows = cast(list[tuple[bytes | str, float]], results[2])
        entries: list[WindowEntry] = []
        for raw, score in rows:
            uid, value = json.loads(raw)
            entries.append(
                WindowEntry(event_uid=str(uid), at_ms=int(score), value=None if value is None else str(value))
            )
        return entries

    async def last_fired(self, key: str) -> int | None:
        _, fired_key = self._keys(key)
        value = await self._redis.get(fired_key)
        return None if value is None else int(value)

    async def mark_fired(self, key: str, at_ms: int, *, window_ms: int) -> None:
        _, fired_key = self._keys(key)
        await self._redis.set(fired_key, at_ms, px=max(_RETENTION_WINDOWS * window_ms, 60_000))
