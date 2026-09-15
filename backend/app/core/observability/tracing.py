"""OpenTelemetry tracing — opt-in (`SENTINELX_OTEL_ENABLED`, requires the `otel` extra)."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from app import __version__
from app.core.config import Settings

logger = logging.getLogger(__name__)


def configure_tracing(app: FastAPI, engine: AsyncEngine, settings: Settings) -> None:
    if not settings.otel_enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:  # pragma: no cover - depends on installed extras
        raise RuntimeError("OpenTelemetry enabled but the 'otel' extra is not installed") from exc

    resource = Resource.create(
        {
            "service.name": "sentinelx-api",
            "service.version": __version__,
            "deployment.environment": settings.environment.value,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = (
        OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint)
        if settings.otel_exporter_endpoint
        else OTLPSpanExporter()
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
    logger.info("OpenTelemetry tracing enabled")
