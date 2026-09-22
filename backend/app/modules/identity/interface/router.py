from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import Container
from app.core.errors import AppError, ValidationFailedError
from app.core.http.deps import get_client_info, get_container, get_principal, get_session, require_permission
from app.core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Page, decode_cursor, encode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import ClientInfo, Principal
from app.modules.identity.application.auth_service import AuthPolicy, AuthService, AuthSession
from app.modules.identity.application.role_service import (
    CreateRoleCommand,
    RoleAdminService,
    UpdateRoleCommand,
)
from app.modules.identity.application.user_service import (
    CreateUserCommand,
    UpdateUserCommand,
    UserAdminService,
)
from app.modules.identity.infrastructure.unit_of_work import SqlIdentityUnitOfWork
from app.modules.identity.interface.schemas import (
    LoginRequest,
    MeResponse,
    PasswordChange,
    PermissionRead,
    RoleAssignment,
    RoleCreate,
    RoleRead,
    RoleUpdate,
    TokenResponse,
    UserCreate,
    UserRead,
    UserUpdate,
)

REFRESH_COOKIE_PATH = "/api/v1/auth"


# ------------------------------------------------------------ dependencies
def get_uow(session: AsyncSession = Depends(get_session)) -> SqlIdentityUnitOfWork:
    return SqlIdentityUnitOfWork(session)


def get_auth_service(
    uow: SqlIdentityUnitOfWork = Depends(get_uow), container: Container = Depends(get_container)
) -> AuthService:
    settings = container.settings
    return AuthService(
        uow,
        hasher=container.password_hasher,
        access_tokens=container.access_tokens,
        blocklist=container.token_blocklist,
        rate_limiter=container.rate_limiter,
        policy=AuthPolicy(
            refresh_ttl_seconds=settings.refresh_token_ttl_seconds,
            login_rate_limit=settings.login_rate_limit,
            login_rate_window_seconds=settings.login_rate_window_seconds,
        ),
    )


def get_user_service(
    uow: SqlIdentityUnitOfWork = Depends(get_uow), container: Container = Depends(get_container)
) -> UserAdminService:
    return UserAdminService(uow, hasher=container.password_hasher)


def get_role_service(uow: SqlIdentityUnitOfWork = Depends(get_uow)) -> RoleAdminService:
    return RoleAdminService(uow)


_optional_bearer = HTTPBearer(auto_error=False)


async def get_optional_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_optional_bearer),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Principal | None:
    """Logout must still work with an expired access token (the refresh cookie suffices)."""
    if credentials is None:
        return None
    try:
        return await get_principal(request, credentials, container, session)
    except AppError:
        return None


def _set_refresh_cookie(response: Response, container: Container, session: AuthSession) -> None:
    settings = container.settings
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=session.refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
        expires=session.refresh_expires_at,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _token_response(session: AuthSession) -> TokenResponse:
    return TokenResponse(
        access_token=session.access.token,
        expires_in=session.access.expires_in,
        expires_at=session.access.expires_at,
    )


def _page_after(cursor: str | None) -> UUID | None:
    if cursor is None:
        return None
    try:
        return UUID(decode_cursor(cursor))
    except ValueError as exc:
        raise ValidationFailedError("Invalid pagination cursor") from exc


# ---------------------------------------------------------------- routers
auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@auth_router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    response: Response,
    client: ClientInfo = Depends(get_client_info),
    service: AuthService = Depends(get_auth_service),
    container: Container = Depends(get_container),
) -> TokenResponse:
    session = await service.login(email=body.email, password=body.password.get_secret_value(), client=client)
    _set_refresh_cookie(response, container, session)
    return _token_response(session)


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    client: ClientInfo = Depends(get_client_info),
    service: AuthService = Depends(get_auth_service),
    container: Container = Depends(get_container),
) -> TokenResponse:
    token = request.cookies.get(container.settings.refresh_cookie_name)
    session = await service.refresh(refresh_token=token, client=client)
    _set_refresh_cookie(response, container, session)
    return _token_response(session)


@auth_router.post(
    "/password",
    response_model=TokenResponse,
    summary="Change your own password (signs out every other session; audited)",
)
async def change_password(
    body: PasswordChange,
    response: Response,
    principal: Principal = Depends(get_principal),
    client: ClientInfo = Depends(get_client_info),
    service: AuthService = Depends(get_auth_service),
    container: Container = Depends(get_container),
) -> TokenResponse:
    session = await service.change_own_password(
        principal,
        current_password=body.current_password.get_secret_value(),
        new_password=body.new_password.get_secret_value(),
        client=client,
    )
    _set_refresh_cookie(response, container, session)
    return _token_response(session)


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    client: ClientInfo = Depends(get_client_info),
    principal: Principal | None = Depends(get_optional_principal),
    service: AuthService = Depends(get_auth_service),
    container: Container = Depends(get_container),
) -> Response:
    settings = container.settings
    await service.logout(
        principal=principal,
        refresh_token=request.cookies.get(settings.refresh_cookie_name),
        client=client,
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        settings.refresh_cookie_name,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return response


jwks_router = APIRouter(tags=["auth"])


@jwks_router.get("/.well-known/jwks.json")
async def jwks(container: Container = Depends(get_container)) -> dict[str, list[dict[str, str]]]:
    """Public verification keys, so other services can validate access tokens without secrets."""
    return container.keyring.jwks()


me_router = APIRouter(prefix="/api/v1", tags=["identity"])


@me_router.get("/me", response_model=MeResponse)
async def me(
    principal: Principal = Depends(get_principal), uow: SqlIdentityUnitOfWork = Depends(get_uow)
) -> MeResponse:
    user = await uow.users.get(principal.org_id, principal.user_id)
    if user is None:  # deleted between principal load and now
        raise ValidationFailedError("Account no longer exists")
    return MeResponse(
        id=user.id,
        org_id=user.org_id,
        email=user.email,
        full_name=user.full_name,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
        last_login_at=user.last_login_at,
    )


users_router = APIRouter(prefix="/api/v1/users", tags=["users"])
PageLimit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]


@users_router.get("", response_model=Page[UserRead])
async def list_users(
    limit: PageLimit = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    principal: Principal = Depends(require_permission(Permission.USER_READ)),
    service: UserAdminService = Depends(get_user_service),
) -> Page[UserRead]:
    page = await service.list_users(principal, limit=limit, after=_page_after(cursor))
    return Page[UserRead](
        items=[UserRead.from_entity(u) for u in page.items],
        next_cursor=None if page.next_after is None else encode_cursor(str(page.next_after)),
    )


@users_router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    principal: Principal = Depends(require_permission(Permission.USER_MANAGE)),
    service: UserAdminService = Depends(get_user_service),
) -> UserRead:
    user = await service.create_user(
        principal,
        CreateUserCommand(
            email=str(body.email),
            full_name=body.full_name,
            password=body.password.get_secret_value(),
            roles=body.roles,
        ),
    )
    return UserRead.from_entity(user)


@users_router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: UUID,
    principal: Principal = Depends(require_permission(Permission.USER_READ)),
    service: UserAdminService = Depends(get_user_service),
) -> UserRead:
    return UserRead.from_entity(await service.get_user(principal, user_id))


@users_router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    principal: Principal = Depends(require_permission(Permission.USER_MANAGE)),
    service: UserAdminService = Depends(get_user_service),
) -> UserRead:
    user = await service.update_user(
        principal,
        user_id,
        UpdateUserCommand(
            full_name=body.full_name,
            is_active=body.is_active,
            password=None if body.password is None else body.password.get_secret_value(),
        ),
    )
    return UserRead.from_entity(user)


@users_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: UUID,
    principal: Principal = Depends(require_permission(Permission.USER_MANAGE)),
    service: UserAdminService = Depends(get_user_service),
) -> Response:
    """Soft delete: accounts are deactivated, never destroyed (docs/05 §8)."""
    await service.deactivate_user(principal, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@users_router.put("/{user_id}/roles", response_model=UserRead)
async def set_user_roles(
    user_id: UUID,
    body: RoleAssignment,
    principal: Principal = Depends(require_permission(Permission.USER_MANAGE)),
    service: UserAdminService = Depends(get_user_service),
) -> UserRead:
    return UserRead.from_entity(await service.set_roles(principal, user_id, body.roles))


roles_router = APIRouter(prefix="/api/v1", tags=["roles"])


@roles_router.get("/roles", response_model=list[RoleRead])
async def list_roles(
    principal: Principal = Depends(require_permission(Permission.ROLE_READ)),
    service: RoleAdminService = Depends(get_role_service),
) -> list[RoleRead]:
    return [RoleRead.from_entity(r) for r in await service.list_roles(principal)]


@roles_router.post("/roles", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreate,
    principal: Principal = Depends(require_permission(Permission.ROLE_MANAGE)),
    service: RoleAdminService = Depends(get_role_service),
) -> RoleRead:
    role = await service.create_role(
        principal,
        CreateRoleCommand(name=body.name, description=body.description, permissions=body.permissions),
    )
    return RoleRead.from_entity(role)


@roles_router.patch("/roles/{role_id}", response_model=RoleRead)
async def update_role(
    role_id: UUID,
    body: RoleUpdate,
    principal: Principal = Depends(require_permission(Permission.ROLE_MANAGE)),
    service: RoleAdminService = Depends(get_role_service),
) -> RoleRead:
    role = await service.update_role(
        principal, role_id, UpdateRoleCommand(description=body.description, permissions=body.permissions)
    )
    return RoleRead.from_entity(role)


@roles_router.get("/permissions", response_model=list[PermissionRead])
async def list_permissions(
    principal: Principal = Depends(require_permission(Permission.ROLE_READ)),
    service: RoleAdminService = Depends(get_role_service),
) -> list[PermissionRead]:
    return [PermissionRead.from_entity(p) for p in await service.list_permissions(principal)]


routers = (auth_router, jwks_router, me_router, users_router, roles_router)
