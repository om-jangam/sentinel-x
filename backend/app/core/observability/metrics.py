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


def render_latest() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
