from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.http.deps import get_session, require_permission
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.threatintel.application.intel_service import IntelQueryService
from app.modules.threatintel.domain.ports import IntelProvider
from app.modules.threatintel.infrastructure.repositories import SqlIntelUnitOfWork
from app.modules.threatintel.interface.schemas import IntelLookup, IntelLookupResponse, IntelResultRead, ProviderRead


def get_intel_service(request: Request, session: AsyncSession = Depends(get_session)) -> IntelQueryService:
    providers = cast(list[IntelProvider], getattr(request.app.state, "intel_providers", []))
    return IntelQueryService(SqlIntelUnitOfWork(session), providers)


router = APIRouter(prefix="/api/v1/intel", tags=["threat intelligence"])


@router.get("/providers", summary="The configured threat-intelligence providers (may be none)")
async def list_providers(
    principal: Principal = Depends(require_permission(Permission.INTEL_READ)),
    service: IntelQueryService = Depends(get_intel_service),
) -> list[ProviderRead]:
    return [ProviderRead.from_info(info) for info in service.providers(principal)]


@router.post(
    "/lookup",
    summary="Cached intel for indicators. Never calls a provider: enrichment runs in the background",
)
async def lookup(
    body: IntelLookup,
    principal: Principal = Depends(require_permission(Permission.INTEL_READ)),
    service: IntelQueryService = Depends(get_intel_service),
) -> IntelLookupResponse:
    results, skipped = await service.results(principal, body.indicators)
    return IntelLookupResponse(results=[IntelResultRead.from_result(r) for r in results], skipped=skipped)


routers = (router,)
