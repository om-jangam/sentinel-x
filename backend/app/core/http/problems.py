"""RFC 9457 `application/problem+json` error responses (docs/06 §2)."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import AppError
from app.core.observability.context import get_correlation_id

logger = logging.getLogger(__name__)

PROBLEM_TYPE_BASE = "https://sentinel-x.dev/errors/"
PROBLEM_MEDIA_TYPE = "application/problem+json"


def problem_response(
    request: Request,
    *,
    status: int,
    type_slug: str,
    title: str,
    detail: str,
    errors: Sequence[Mapping[str, Any]] = (),
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = {
        "type": PROBLEM_TYPE_BASE + type_slug,
        "title": title,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
        "correlation_id": get_correlation_id(),
        "errors": list(errors),
    }
    return JSONResponse(body, status_code=status, headers=dict(headers or {}), media_type=PROBLEM_MEDIA_TYPE)


def _slug(status: int) -> str:
    try:
        return HTTPStatus(status).phrase.lower().replace(" ", "-")
    except ValueError:
        return "http-error"


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return problem_response(
            request,
            status=exc.status,
            type_slug=exc.type_slug,
            title=exc.title,
            detail=exc.detail,
            errors=exc.errors,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo `input`: request bodies can carry passwords and tokens.
        errors = [
            {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in exc.errors()
        ]
        return problem_response(
            request,
            status=422,
            type_slug="validation-failed",
            title="Validation failed",
            detail="The request is invalid",
            errors=errors,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        status = exc.status_code
        phrase = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "HTTP error"
        return problem_response(
            request,
            status=status,
            type_slug=_slug(status),
            title=phrase,
            detail=str(exc.detail) if exc.detail else phrase,
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error", extra={"path": request.url.path})
        return problem_response(
            request,
            status=500,
            type_slug="internal-error",
            title="Internal server error",
            detail="An unexpected error occurred",
        )
