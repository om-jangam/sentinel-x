"""FastAPI application factory — the composition root.

Run with: `uvicorn app.main:create_app --factory`
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.core.config import Environment, Settings, get_settings
from app.core.container import build_container
from app.core.events.bus import InMemoryEventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.core.http.problems import install_exception_handlers
from app.core.observability.logging import configure_logging
from app.core.observability.middleware import (
    CORRELATION_HEADER,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.observability.tracing import configure_tracing
from app.modules.identity.infrastructure.principal_loader import SqlPrincipalLoader
from app.modules.identity.interface import router as identity_api
from app.modules.ingestion.application.indexing_service import IndexingService
from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings
from app.modules.ingestion.interface import router as ingestion_api
from app.modules.platform.interface import router as platform_api

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    if settings.environment is not Environment.TEST:
        configure_logging(level=settings.log_level, json_output=settings.log_json)

    container = build_container(settings)
    container.principal_loader = SqlPrincipalLoader()
    event_store = event_store_from_settings(settings)

    # Without Redis there is no worker to consume the bus, so the API indexes in-process.
    if event_store is not None and isinstance(container.event_bus, InMemoryEventBus):
        container.event_bus.subscribe(EVENTS_NORMALIZED, IndexingService(event_store).handle)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if event_store is not None:
            try:
                await event_store.ensure_ready()
            except Exception:
                # A cold or unreachable cluster must not stop the API booting; /readyz reports it.
                logger.warning("could not prepare the event store", exc_info=True)
        yield
        if event_store is not None:
            await event_store.aclose()
        await container.aclose()

    docs = settings.expose_api_docs
    app = FastAPI(
        title="Sentinel-X API",
        version=__version__,
        description="Autonomous AI Security Operations Platform",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.container = container
    app.state.event_store = event_store
    install_exception_handlers(app)

    # Starlette runs the last-added middleware outermost.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", CORRELATION_HEADER, "Idempotency-Key"],
        expose_headers=[CORRELATION_HEADER, "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)
    app.add_middleware(RequestContextMiddleware, metrics_enabled=settings.metrics_enabled)

    for router in (*identity_api.routers, *ingestion_api.routers, *platform_api.routers):
        app.include_router(router)

    configure_tracing(app, container.database.engine, settings)
    return app
