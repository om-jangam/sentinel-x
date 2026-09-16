"""Prometheus metrics. Served on `/metrics`, which must stay on the internal network (docs/07 §6)."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest

REGISTRY = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "sentinelx_http_requests_total",
    "HTTP requests by route template and status",
    ["method", "route", "status"],
    registry=REGISTRY,
)
HTTP_LATENCY = Histogram(
    "sentinelx_http_request_duration_seconds",
    "HTTP request latency by route template",
    ["method", "route"],
    registry=REGISTRY,
)
AUTH_EVENTS = Counter(
    "sentinelx_auth_events_total",
    "Authentication outcomes",
    ["event", "outcome"],
    registry=REGISTRY,
)
AUDIT_WRITES = Counter(
    "sentinelx_audit_writes_total",
    "Audit log entries appended",
    ["action"],
    registry=REGISTRY,
)


INGEST_EVENTS = Counter(
    "sentinelx_ingest_events_total",
    "Records submitted to the ingest API by parser and outcome",
    ["parser", "outcome"],
    registry=REGISTRY,
)
INDEXED_EVENTS = Counter(
    "sentinelx_indexed_events_total",
    "Normalised events written to the event store by outcome",
    ["outcome"],
    registry=REGISTRY,
)
INGEST_LAG = Histogram(
    "sentinelx_ingest_lag_seconds",
    "Delay between accepting an event and indexing it",
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300),
    registry=REGISTRY,
)
EVENT_AGE = Histogram(
    "sentinelx_event_age_seconds",
    "Delay between an event happening at the source and being indexed",
    buckets=(1, 5, 15, 60, 300, 900, 3600, 21600, 86400),
    registry=REGISTRY,
)


def render_latest() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
