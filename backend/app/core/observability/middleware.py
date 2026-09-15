"""Pure-ASGI middleware: correlation IDs, request metrics, security headers."""

from __future__ import annotations

import re
import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.ids import uuid7
from app.core.observability.context import correlation_id_var
from app.core.observability.metrics import HTTP_LATENCY, HTTP_REQUESTS

CORRELATION_HEADER = "X-Correlation-ID"
_VALID_CORRELATION_ID = re.compile(r"[A-Za-z0-9._\-]{1,128}")


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, *, metrics_enabled: bool = True) -> None:
        self.app = app
        self.metrics_enabled = metrics_enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get(CORRELATION_HEADER)
        # Untrusted input: only echo well-formed IDs (prevents header/log injection).
        correlation_id = incoming if incoming and _VALID_CORRELATION_ID.fullmatch(incoming) else str(uuid7())
        correlation_id_var.set(correlation_id)

        status_code = 500
        started = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message).append(CORRELATION_HEADER, correlation_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if self.metrics_enabled and scope["type"] == "http":
                route = scope.get("route")
                # Route templates, never raw paths — keeps label cardinality bounded.
                template = getattr(route, "path", "unmatched")
                method = scope["method"]
                HTTP_REQUESTS.labels(method=method, route=template, status=str(status_code)).inc()
                HTTP_LATENCY.labels(method=method, route=template).observe(time.perf_counter() - started)


_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                if not path.startswith(_DOCS_PATHS):
                    headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                if path.startswith("/api/"):
                    headers.setdefault("Cache-Control", "no-store")
                if self.hsts:
                    headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, send_wrapper)
