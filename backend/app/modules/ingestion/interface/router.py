from __future__ import annotations

import json
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import utcnow
from app.core.container import Container
from app.core.errors import (
    AuthenticationError,
    PayloadTooLargeError,
    RateLimitedError,
    ServiceUnavailableError,
    ValidationFailedError,
)
from app.core.http.deps import get_container, get_session, require_permission
from app.core.pagination import decode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.ingest_pipeline.parsers import PARSER_DESCRIPTIONS
from app.modules.ingestion.application.event_service import EventQueryService
from app.modules.ingestion.application.ingest_service import IngestService
from app.modules.ingestion.application.source_service import (
    CreateSourceCommand,
    SourceAdminService,
)
from app.modules.ingestion.domain.entities import IngestSource
from app.modules.ingestion.domain.events import EventCursor, EventQuery
from app.modules.ingestion.domain.policies import MAX_BODY_BYTES, is_ingest_token
from app.modules.ingestion.domain.ports import EventStore
from app.modules.ingestion.infrastructure.unit_of_work import SqlIngestionUnitOfWork
from app.modules.ingestion.interface.schemas import (
    EventPageResponse,
    EventSearchRequest,
    IngestErrorRead,
    IngestResponse,
    ParserRead,
    SourceCreate,
    SourceRead,
    SourceUpdate,
    SourceWithToken,
)


# ------------------------------------------------------------ dependencies
def get_uow(session: AsyncSession = Depends(get_session)) -> SqlIngestionUnitOfWork:
    return SqlIngestionUnitOfWork(session)


def get_source_service(uow: SqlIngestionUnitOfWork = Depends(get_uow)) -> SourceAdminService:
    return SourceAdminService(uow)


def get_event_store(request: Request) -> EventStore:
    store = getattr(request.app.state, "event_store", None)
    if store is None:
        raise ServiceUnavailableError("The event store is not configured (SENTINELX_OPENSEARCH_URL)")
    return cast(EventStore, store)


def get_event_service(store: EventStore = Depends(get_event_store)) -> EventQueryService:
    return EventQueryService(store)


def get_ingest_service(
    uow: SqlIngestionUnitOfWork = Depends(get_uow), container: Container = Depends(get_container)
) -> IngestService:
    return IngestService(uow, bus=container.event_bus)


async def resolve_ingest_source(
    request: Request,
    source_id: UUID | None = Query(default=None, description="Required when using a user access token"),
    uow: SqlIngestionUnitOfWork = Depends(get_uow),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> IngestSource:
    """Authenticate a producer: a source ingest token, or a user holding `ingest:write`."""
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not credential:
        raise AuthenticationError()

    if is_ingest_token(credential):
        return await SourceAdminService(uow).authenticate(credential)

    claims = container.access_tokens.verify(credential)
    if await container.token_blocklist.is_blocked(claims.jti):
        raise AuthenticationError("Access token has been revoked")
    if container.principal_loader is None:  # wiring bug, not a client error
        raise RuntimeError("no PrincipalLoader registered")
    principal = await container.principal_loader.load(session, claims)
    principal.require(Permission.INGEST_WRITE)
    if source_id is None:
        raise ValidationFailedError(
            "source_id is required",
            errors=[{"loc": ["query", "source_id"], "msg": "required with a user token", "type": "missing"}],
        )
    source = await uow.sources.get(principal.org_id, source_id)
    if source is None:
        raise ValidationFailedError(
            "Unknown ingest source",
            errors=[{"loc": ["query", "source_id"], "msg": "no such source", "type": "unknown_source"}],
        )
    return source


def _parse_records(body: bytes, content_type: str) -> list[dict[str, Any]]:
    """Vector's http sink sends a JSON array; agents may send NDJSON or a single object."""
    if not body.strip():
        return []
    try:
        if "ndjson" in content_type:
            parsed: Any = [json.loads(line) for line in body.splitlines() if line.strip()]
        else:
            parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationFailedError(f"Malformed request body: {exc}") from exc

    if isinstance(parsed, dict):
        parsed = parsed["events"] if isinstance(parsed.get("events"), list) else [parsed]
    if not isinstance(parsed, list):
        raise ValidationFailedError("Body must be an event object, an array, or NDJSON")
    if not all(isinstance(record, dict) for record in parsed):
        raise ValidationFailedError("Every event must be a JSON object")
    return parsed


ingest_router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])
events_router = APIRouter(prefix="/api/v1/events", tags=["events"])


# ----------------------------------------------------------------- ingest
@ingest_router.post("/events", status_code=status.HTTP_202_ACCEPTED, summary="Submit telemetry")
async def ingest_events(
    request: Request,
    source: IngestSource = Depends(resolve_ingest_source),
    service: IngestService = Depends(get_ingest_service),
    container: Container = Depends(get_container),
) -> IngestResponse:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise PayloadTooLargeError(f"At most {MAX_BODY_BYTES // 1024} KiB per request")

    settings = container.settings
    decision = await container.rate_limiter.hit(
        f"ingest:{source.id}",
        limit=settings.ingest_rate_limit,
        window_seconds=settings.ingest_rate_window_seconds,
    )
    if not decision.allowed:
        raise RateLimitedError(decision.retry_after_seconds)

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise PayloadTooLargeError(f"At most {MAX_BODY_BYTES // 1024} KiB per request")

    result = await service.ingest(source=source, records=_parse_records(body, request.headers.get("content-type", "")))
    return IngestResponse(
        accepted=result.accepted,
        rejected=result.rejected,
        errors=[IngestErrorRead(index=e.index, reason=e.reason) for e in result.errors],
    )


@ingest_router.get("/parsers", summary="Supported source parsers")
async def list_parsers(
    _: Principal = Depends(require_permission(Permission.SOURCE_READ)),
) -> list[ParserRead]:
    return [ParserRead(name=name, description=description) for name, description in sorted(PARSER_DESCRIPTIONS.items())]


# ---------------------------------------------------------------- sources
@ingest_router.get("/sources", summary="List ingest sources")
async def list_sources(
    principal: Principal = Depends(require_permission(Permission.SOURCE_READ)),
    service: SourceAdminService = Depends(get_source_service),
) -> list[SourceRead]:
    now = utcnow()
    sources = await service.list_sources(principal)
    return [SourceRead.from_entity(source, now=now) for source in sources]


@ingest_router.post("/sources", status_code=status.HTTP_201_CREATED, summary="Register an ingest source")
async def create_source(
    payload: SourceCreate,
    principal: Principal = Depends(require_permission(Permission.SOURCE_MANAGE)),
    service: SourceAdminService = Depends(get_source_service),
) -> SourceWithToken:
    issued = await service.create_source(
        principal,
        CreateSourceCommand(name=payload.name, description=payload.description, parser=payload.parser),
    )
    return SourceWithToken(source=SourceRead.from_entity(issued.source, now=utcnow()), token=issued.token)


@ingest_router.get("/sources/{source_id}", summary="Inspect an ingest source")
async def get_source(
    source_id: UUID,
    principal: Principal = Depends(require_permission(Permission.SOURCE_READ)),
    service: SourceAdminService = Depends(get_source_service),
) -> SourceRead:
    return SourceRead.from_entity(await service.get_source(principal, source_id), now=utcnow())


@ingest_router.patch("/sources/{source_id}", summary="Enable or disable an ingest source")
async def update_source(
    source_id: UUID,
    payload: SourceUpdate,
    principal: Principal = Depends(require_permission(Permission.SOURCE_MANAGE)),
    service: SourceAdminService = Depends(get_source_service),
) -> SourceRead:
    source = await service.set_enabled(principal, source_id, enabled=payload.is_enabled)
    return SourceRead.from_entity(source, now=utcnow())


@ingest_router.post("/sources/{source_id}/rotate-token", summary="Issue a new ingest token")
async def rotate_source_token(
    source_id: UUID,
    principal: Principal = Depends(require_permission(Permission.SOURCE_MANAGE)),
    service: SourceAdminService = Depends(get_source_service),
) -> SourceWithToken:
    issued = await service.rotate_token(principal, source_id)
    return SourceWithToken(source=SourceRead.from_entity(issued.source, now=utcnow()), token=issued.token)


# ----------------------------------------------------------------- events
@events_router.post("/search", summary="Search normalised events")
async def search_events(
    payload: EventSearchRequest,
    principal: Principal = Depends(require_permission(Permission.EVENT_READ)),
    service: EventQueryService = Depends(get_event_service),
) -> EventPageResponse:
    query = EventQuery(
        time_from=payload.time_from,
        time_to=payload.time_to,
        class_uids=tuple(payload.class_uids),
        severity_min=payload.severity_min,
        status_id=payload.status_id,
        text=payload.text,
        ip=payload.ip,
        user_name=payload.user_name,
        hostname=payload.hostname,
        source_id=payload.source_id,
        limit=payload.limit,
        cursor=EventCursor.decode(decode_cursor(payload.cursor)) if payload.cursor else None,
    )
    return EventPageResponse.from_page(await service.search(principal, query))


@events_router.get("/{event_uid}", summary="Fetch one event")
async def get_event(
    event_uid: str,
    principal: Principal = Depends(require_permission(Permission.EVENT_READ)),
    service: EventQueryService = Depends(get_event_service),
) -> dict[str, Any]:
    return await service.get(principal, event_uid)


routers = (ingest_router, events_router)
