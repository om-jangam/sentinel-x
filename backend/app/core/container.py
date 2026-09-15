"""Process-wide service container, built once per app instance (composition root input)."""

from __future__ import annotations

from dataclasses import dataclass, field

from redis.asyncio import Redis

from app.core.config import Settings
from app.core.db.session import Database
from app.core.events.bus import EventBus, InMemoryEventBus
from app.core.events.redis_streams import RedisStreamsEventBus
from app.core.http.auth import PrincipalLoader
from app.core.security.blocklist import InMemoryTokenBlocklist, RedisTokenBlocklist, TokenBlocklist
from app.core.security.keys import KeyRing, load_keyring
from app.core.security.passwords import PasswordHasher
from app.core.security.ratelimit import InMemoryRateLimiter, RateLimiter, RedisRateLimiter
from app.core.security.tokens import AccessTokenService


@dataclass
class Container:
    settings: Settings
    database: Database
    keyring: KeyRing
    access_tokens: AccessTokenService
    password_hasher: PasswordHasher
    token_blocklist: TokenBlocklist
    rate_limiter: RateLimiter
    event_bus: EventBus
    redis: Redis | None = None
    principal_loader: PrincipalLoader | None = field(default=None)

    async def ping_redis(self) -> bool | None:
        """None when Redis isn't configured (lite/dev), else reachability."""
        if self.redis is None:
            return None
        try:
            return bool(await self.redis.ping())
        except Exception:
            return False

    async def aclose(self) -> None:
        await self.database.dispose()
        if self.redis is not None:
            await self.redis.aclose()


def build_container(settings: Settings) -> Container:
    keyring = load_keyring(settings)
    redis = Redis.from_url(settings.redis_url) if settings.redis_url else None
    return Container(
        settings=settings,
        database=Database(settings.database_url, echo=settings.database_echo),
        keyring=keyring,
        access_tokens=AccessTokenService(
            keyring,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            ttl_seconds=settings.access_token_ttl_seconds,
        ),
        password_hasher=PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost_kib=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
        ),
        token_blocklist=RedisTokenBlocklist(redis) if redis else InMemoryTokenBlocklist(),
        rate_limiter=RedisRateLimiter(redis) if redis else InMemoryRateLimiter(),
        event_bus=RedisStreamsEventBus(redis) if redis else InMemoryEventBus(),
        redis=redis,
    )
