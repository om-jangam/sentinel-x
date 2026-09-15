"""Relational engine and session factory (PostgreSQL in every real deployment)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Database:
    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        is_sqlite = url.startswith("sqlite")
        self.engine: AsyncEngine = create_async_engine(url, echo=echo, pool_pre_ping=not is_sqlite)
        if is_sqlite:
            event.listen(self.engine.sync_engine, "connect", _enable_sqlite_foreign_keys)
        self.sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, autoflush=False
        )

    @property
    def dialect_name(self) -> str:
        return self.engine.dialect.name

    async def ping(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    async def dispose(self) -> None:
        await self.engine.dispose()
