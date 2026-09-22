"""FastAPI application factory — the composition root.

Run with: `uvicorn app.main:create_app --factory`
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.analysis import build_analysis
from app.core.config import Environment, Settings, get_settings
from app.core.container import build_container
from app.core.events.bus import InMemoryEventBus
from app.core.events.topics import EVENTS_NORMALIZED, INCIDENTS_CHANGED
from app.core.http.problems import install_exception_handlers
from app.core.observability.logging import configure_logging
from app.core.observability.middleware import (
    CORRELATION_HEADER,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.observability.tracing import configure_tracing
from app.modules.correlation.interface import router as correlation_api
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore, RedisWindowStore
from app.modules.detection.interface import router as detection_api
from app.modules.identity.infrastructure.principal_loader import SqlPrincipalLoader
from app.modules.identity.interface import router as identity_api
from app.modules.ingestion.application.indexing_service import IndexingService
from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings
from app.modules.ingestion.interface import router as ingestion_api
from app.modules.platform.interface import router as platform_api
from app.modules.threatintel.application.enrichment_service import EnrichmentService
from app.modules.threatintel.infrastructure.providers import providers_from_settings
from app.modules.threatintel.infrastructure.repositories import sql_uow_factory as intel_uow_factory
from app.modules.threatintel.interface import router as intel_api

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    if settings.environment is not Environment.TEST:
        configure_logging(level=settings.log_level, json_output=settings.log_json)

    container = build_container(settings)
    container.principal_loader = SqlPrincipalLoader()
    event_store = event_store_from_settings(settings)

    # Rules are code: a rule that can't load stops start-up rather than silently never firing.
    detection_rules = load_rules()
    intel_providers = providers_from_settings(settings)

    # Without Redis there is no worker to consume the bus, so the API indexes, detects and correlates in-process.
    if isinstance(container.event_bus, InMemoryEventBus):
        if event_store is not None:
            container.event_bus.subscribe(EVENTS_NORMALIZED, IndexingService(event_store).handle)
        detection = build_analysis(
            detection_rules,
            container.database,
            RedisWindowStore(container.redis) if container.redis is not None else InMemoryWindowStore(),
            lookup=None if event_store is None else event_store.get_many,
            publish=container.event_bus.publish,
        )
        container.event_bus.subscribe(EVENTS_NORMALIZED, detection.handle)
        if intel_providers:
            enrichment = EnrichmentService(
                intel_providers,
                uow_factory=intel_uow_factory(container.database),
                cache_ttl=timedelta(hours=settings.ti_cache_hours),
            )
            container.event_bus.subscribe(INCIDENTS_CHANGED, enrichment.handle)

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
        for provider in intel_providers:
            await provider.aclose()
        await container.aclose()

    docs = settings.expose_api_docs
    app = FastAPI(
        title="Sentinel-X API",
        version=__version__,
        description=(
            "AI-assisted security investigation platform: correlates security telemetry, reconstructs "
            "attack timelines and entity relationships, and assists analysts with evidence-backed findings."
        ),
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.container = container
    app.state.event_store = event_store
    app.state.detection_rules = detection_rules
    app.state.intel_providers = intel_providers
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

    for router in (
        *identity_api.routers,
        *ingestion_api.routers,
        *detection_api.routers,
        *correlation_api.routers,
        *intel_api.routers,
        *platform_api.routers,
    ):
        app.include_router(router)

    configure_tracing(app, container.database.engine, settings)
    return app
