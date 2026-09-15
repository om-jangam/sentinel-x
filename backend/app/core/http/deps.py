"""FastAPI dependencies shared by every module's interface layer."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import cast

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import Container
from app.core.errors import AuthenticationError
from app.core.security.principal import ClientInfo, Principal

_bearer = HTTPBearer(auto_error=False, description="Access JWT from POST /api/v1/auth/login")


def get_container(request: Request) -> Container:
    return cast(Container, request.app.state.container)


async def get_session(container: Container = Depends(get_container)) -> AsyncIterator[AsyncSession]:
    """One session per request. Use-cases commit explicitly; anything uncommitted rolls back."""
    async with container.database.sessionmaker() as session:
        yield session


def get_client_info(request: Request) -> ClientInfo:
    user_agent = request.headers.get("user-agent")
    return ClientInfo(
        ip=request.client.host if request.client else None,
        user_agent=user_agent[:256] if user_agent else None,
    )


async def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Principal:
    if credentials is None:
        raise AuthenticationError()
    claims = container.access_tokens.verify(credentials.credentials)
    if await container.token_blocklist.is_blocked(claims.jti):
        raise AuthenticationError("Access token has been revoked")
    if container.principal_loader is None:  # wiring bug, not a client error
        raise RuntimeError("no PrincipalLoader registered")
    principal = await container.principal_loader.load(session, claims)
    request.state.principal = principal
    return principal


def require_permission(permission: str) -> Callable[..., Awaitable[Principal]]:
    """Route-level guard. Use-cases re-check via `Principal.require` (defence in depth)."""

    async def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        principal.require(permission)
        return principal

    return dependency
