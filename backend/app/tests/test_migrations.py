"""The Alembic history must produce exactly the schema the ORM models describe."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from app.core.config import Settings
from app.core.db.session import Database
from app.model_registry import metadata

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _config(connection: Connection) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "app" / "migrations"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    return config


def _upgrade(connection: Connection) -> None:
    connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    metadata.drop_all(connection)
    if connection.dialect.name == "postgresql":
        connection.execute(text("DROP FUNCTION IF EXISTS audit_log_block_mutation() CASCADE"))
    command.upgrade(_config(connection), "head")


def _diff(connection: Connection) -> list[Any]:
    context = MigrationContext.configure(connection, opts={"compare_type": True})
    return list(compare_metadata(context, metadata))


async def test_migrations_match_models(settings: Settings) -> None:
    database = Database(settings.database_url)
    try:
        async with database.engine.begin() as conn:
            await conn.run_sync(_upgrade)
            diff = await conn.run_sync(_diff)
        assert diff == [], f"models and migrations have drifted: {diff}"
    finally:
        async with database.engine.begin() as conn:
            await conn.run_sync(lambda c: command.downgrade(_config(c), "base"))
        await database.dispose()


async def test_audit_log_is_append_only_on_postgres(settings: Settings) -> None:
    if not settings.database_url.startswith("postgresql"):
        pytest.skip("append-only trigger is PostgreSQL-specific")
    database = Database(settings.database_url)
    try:
        async with database.engine.begin() as conn:
            await conn.run_sync(_upgrade)
        async with database.engine.connect() as conn:
            with pytest.raises(DBAPIError, match="append-only"):
                await conn.execute(text("DELETE FROM audit_log"))
    finally:
        async with database.engine.begin() as conn:
            await conn.run_sync(lambda c: command.downgrade(_config(c), "base"))
        await database.dispose()
