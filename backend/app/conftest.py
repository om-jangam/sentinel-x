"""Shared test fixtures.

Tests run against SQLite by default. Set SENTINELX_TEST_DATABASE_URL (CI does) to run the same
suite against PostgreSQL.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI

from app.core.config import Environment, Settings
from app.core.container import Container
from app.main import create_app
from app.model_registry import metadata
from app.modules.identity.application.bootstrap import bootstrap_platform, create_initial_admin
from app.modules.identity.domain.entities import Org, User
from app.modules.identity.infrastructure.unit_of_work import SqlIdentityUnitOfWork

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def settings(tmp_path: os.PathLike[str]) -> Settings:
    url = os.environ.get("SENTINELX_TEST_DATABASE_URL") or f"sqlite+aiosqlite:///{os.fspath(tmp_path)}/test.db"
    return Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_url=url,
        redis_url=None,
        cookie_secure=True,
        argon2_time_cost=1,
        argon2_memory_cost_kib=64,
        argon2_parallelism=1,
        login_rate_limit=5,
        login_rate_window_seconds=60,
    )


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    container: Container = application.state.container
    async with container.database.engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)
    yield application
    await container.aclose()


@pytest.fixture
def container(app: FastAPI) -> Container:
    result: Container = app.state.container
    return result


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    # https base URL so Secure refresh cookies are sent back, as in a real browser.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as http:
        yield http


@dataclass(frozen=True)
class Seeded:
    org: Org
    admin: User
    admin_email: str
    admin_password: str


@pytest.fixture
async def seeded(container: Container) -> Seeded:
    async with container.database.sessionmaker() as session:
        uow = SqlIdentityUnitOfWork(session)
        result = await bootstrap_platform(uow, org_name="Acme SOC", org_slug="acme")
        admin = await create_initial_admin(
            uow,
            container.password_hasher,
            org=result.org,
            email=ADMIN_EMAIL,
            full_name="Ada Admin",
            password=ADMIN_PASSWORD,
        )
    return Seeded(org=result.org, admin=admin, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD)


async def login(client: httpx.AsyncClient, email: str, password: str) -> str:
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    if response.status_code != 200:
        raise AssertionError(f"login failed: {response.status_code} {response.text}")
    token: str = response.json()["access_token"]
    return token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin_token(client: httpx.AsyncClient, seeded: Seeded) -> str:
    return await login(client, seeded.admin_email, seeded.admin_password)
