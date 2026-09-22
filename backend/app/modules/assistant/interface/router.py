from __future__ import annotations

from collections.abc import Callable
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceUnavailableError
from app.core.http.deps import get_session, require_permission
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.assistant.application.assistant_service import AssistantService
from app.modules.assistant.domain.ports import BundleSource, LanguageModel
from app.modules.assistant.infrastructure.storage import SqlAssistantUnitOfWork
from app.modules.assistant.interface.schemas import AnalysisRead, AssistantStatusRead

BundleSourceFactory = Callable[[AsyncSession], BundleSource]


def get_assistant(request: Request, session: AsyncSession = Depends(get_session)) -> AssistantService:
    factory = getattr(request.app.state, "bundle_source_factory", None)
    if factory is None:  # wiring bug, not a client error
        raise ServiceUnavailableError("The assistant is not wired")
    model = cast(LanguageModel | None, getattr(request.app.state, "language_model", None))
    return AssistantService(
        model=model, bundles=cast(BundleSourceFactory, factory)(session), uow=SqlAssistantUnitOfWork(session)
    )


router = APIRouter(tags=["assistant"])


@router.get("/api/v1/assistant", summary="Whether the AI assistant is configured, and with which model")
async def assistant_status(
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: AssistantService = Depends(get_assistant),
) -> AssistantStatusRead:
    return AssistantStatusRead.from_status(service.status(principal))


@router.get("/api/v1/incidents/{incident_id}/analyses", summary="Recorded AI analyses of an incident, newest first")
async def list_analyses(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: AssistantService = Depends(get_assistant),
) -> list[AnalysisRead]:
    return [AnalysisRead.from_record(record) for record in await service.history(principal, incident_id)]


@router.post(
    "/api/v1/incidents/{incident_id}/analyses",
    status_code=status.HTTP_201_CREATED,
    summary="Ask the AI assistant to analyse an incident (recorded and audited, whatever the outcome)",
)
async def analyse(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.ASSISTANT_USE)),
    service: AssistantService = Depends(get_assistant),
) -> AnalysisRead:
    return AnalysisRead.from_record(await service.analyse(principal, incident_id))


routers = (router,)
