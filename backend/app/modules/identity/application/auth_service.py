"""Login, refresh-token rotation with reuse detection, and logout (ADR-0010)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import AuthenticationError, RateLimitedError, ValidationFailedError
from app.core.ids import uuid7
from app.core.observability.metrics import AUTH_EVENTS
from app.core.security.blocklist import TokenBlocklist
from app.core.security.passwords import PasswordHasher
from app.core.security.principal import ClientInfo, Principal
from app.core.security.ratelimit import RateLimiter
from app.core.security.tokens import (
    AccessTokenService,
    IssuedAccessToken,
    generate_opaque_token,
    hash_opaque_token,
)
from app.modules.identity.domain.entities import RefreshToken, User
from app.modules.identity.domain.policies import normalize_email, validate_password
from app.modules.identity.domain.ports import IdentityUnitOfWork

logger = logging.getLogger(__name__)

GENERIC_LOGIN_FAILURE = "Invalid email or password"
# Many analysts can share one egress IP, so the per-IP budget is wider than per-account.
IP_LIMIT_MULTIPLIER = 5


@dataclass(frozen=True, slots=True)
class AuthPolicy:
    refresh_ttl_seconds: int
    login_rate_limit: int
    login_rate_window_seconds: int


@dataclass(frozen=True, slots=True)
class AuthSession:
    user: User
    access: IssuedAccessToken
    refresh_token: str
    refresh_expires_at: datetime


class AuthService:
    def __init__(
        self,
        uow: IdentityUnitOfWork,
        *,
        hasher: PasswordHasher,
        access_tokens: AccessTokenService,
        blocklist: TokenBlocklist,
        rate_limiter: RateLimiter,
        policy: AuthPolicy,
        clock: Clock = utcnow,
    ) -> None:
        self._uow = uow
        self._hasher = hasher
        self._access_tokens = access_tokens
        self._blocklist = blocklist
        self._rate_limiter = rate_limiter
        self._policy = policy
        self._clock = clock

    # ------------------------------------------------------------------ login
    async def login(self, *, email: str, password: str, client: ClientInfo) -> AuthSession:
        normalized = normalize_email(email)
        await self._enforce_login_rate_limit(normalized, client)

        user = await self._uow.users.get_by_email(normalized)
        if user is None:
            self._hasher.burn(password)  # equal work, so account existence can't be timed
            AUTH_EVENTS.labels(event="login", outcome="unknown_account").inc()
            logger.info("login failed", extra={"reason": "unknown_account"})
            raise AuthenticationError(GENERIC_LOGIN_FAILURE)

        valid, rehashed = self._hasher.verify(password, user.hashed_password)
        if not valid or not user.is_active:
            reason = "invalid_password" if not valid else "inactive_account"
            await self._audit_user(user, "auth.login_failed", client, reason=reason)
            await self._uow.commit()
            AUTH_EVENTS.labels(event="login", outcome=reason).inc()
            raise AuthenticationError(GENERIC_LOGIN_FAILURE)

        now = self._clock()
        user.last_login_at = now
        if rehashed is not None:
            user.hashed_password = rehashed
        await self._uow.users.update(user)
        session = await self._open_session(user, family_id=uuid7(), now=now)
        await self._audit_user(user, "auth.login_succeeded", client)
        await self._uow.commit()
        AUTH_EVENTS.labels(event="login", outcome="success").inc()
        return session

    async def _enforce_login_rate_limit(self, email: str, client: ClientInfo) -> None:
        limit = self._policy.login_rate_limit
        window = self._policy.login_rate_window_seconds
        checks = [(f"login:account:{email}", limit)]
        if client.ip:
            checks.append((f"login:ip:{client.ip}", limit * IP_LIMIT_MULTIPLIER))
        for key, key_limit in checks:
            decision = await self._rate_limiter.hit(key, limit=key_limit, window_seconds=window)
            if not decision.allowed:
                AUTH_EVENTS.labels(event="login", outcome="rate_limited").inc()
                raise RateLimitedError(decision.retry_after_seconds)

    # ---------------------------------------------------------------- refresh
    async def refresh(self, *, refresh_token: str | None, client: ClientInfo) -> AuthSession:
        if not refresh_token:
            raise AuthenticationError("Refresh token missing")
        stored = await self._uow.refresh_tokens.get_by_hash(hash_opaque_token(refresh_token))
        if stored is None:
            AUTH_EVENTS.labels(event="refresh", outcome="unknown_token").inc()
            raise AuthenticationError("Invalid refresh token")

        now = self._clock()
        if stored.used_at is not None:
            await self._handle_reuse(stored, client, now)
        if stored.revoked_at is not None:
            raise AuthenticationError("Refresh token has been revoked")
        if stored.expires_at <= now:
            raise AuthenticationError("Refresh token expired")
        if not await self._uow.refresh_tokens.mark_used(stored.id, now):
            # Lost a race with another request presenting the same token: treat as replay.
            await self._handle_reuse(stored, client, now)

        user = await self._uow.users.get(stored.org_id, stored.user_id)
        if user is None or not user.is_active:
            await self._uow.refresh_tokens.revoke_family(stored.family_id, now)
            await self._uow.commit()
            raise AuthenticationError("Account is inactive")

        session = await self._open_session(user, family_id=stored.family_id, now=now)
        await self._uow.commit()
        AUTH_EVENTS.labels(event="refresh", outcome="success").inc()
        return session

    async def _handle_reuse(self, stored: RefreshToken, client: ClientInfo, now: datetime) -> None:
        revoked = await self._uow.refresh_tokens.revoke_family(stored.family_id, now)
        await self._uow.audit.record(
            AuditEvent(
                org_id=stored.org_id,
                action="auth.refresh_token_reuse_detected",
                resource_type="user",
                resource_id=str(stored.user_id),
                actor_type="system",
                context={
                    **client.as_audit_context(),
                    "family_id": str(stored.family_id),
                    "tokens_revoked": revoked,
                },
            )
        )
        await self._uow.commit()
        AUTH_EVENTS.labels(event="refresh", outcome="reuse_detected").inc()
        logger.warning("refresh token reuse detected; token family revoked")
        raise AuthenticationError("Refresh token reuse detected; the session has been revoked")

    # ----------------------------------------------------------------- logout
    async def logout(self, *, principal: Principal | None, refresh_token: str | None, client: ClientInfo) -> None:
        now = self._clock()
        org_id: UUID | None = None
        user_id: UUID | None = None

        if refresh_token:
            stored = await self._uow.refresh_tokens.get_by_hash(hash_opaque_token(refresh_token))
            if stored is not None:
                await self._uow.refresh_tokens.revoke_family(stored.family_id, now)
                org_id, user_id = stored.org_id, stored.user_id
        if principal is not None:
            if principal.token_jti and principal.token_expires_at:
                await self._blocklist.block(principal.token_jti, principal.token_expires_at)
            org_id, user_id = principal.org_id, principal.user_id

        if org_id is not None and user_id is not None:
            await self._uow.audit.record(
                AuditEvent(
                    org_id=org_id,
                    action="auth.logout",
                    resource_type="user",
                    resource_id=str(user_id),
                    actor_id=user_id,
                    context=client.as_audit_context(),
                )
            )
        await self._uow.commit()

    # -------------------------------------------------------- change password
    async def change_own_password(
        self, principal: Principal, *, current_password: str, new_password: str, client: ClientInfo
    ) -> AuthSession:
        """Self-service change. Signs out every session, then opens a fresh one for this browser.

        The current password is required even with a valid access token, so a stolen token or an unattended
        browser can't take the account over. Wrong guesses share the login rate limit's budget per account.
        """
        user = await self._uow.users.get(principal.org_id, principal.user_id)
        if user is None or not user.is_active:
            raise AuthenticationError("Account is inactive")
        decision = await self._rate_limiter.hit(
            f"password:account:{user.id}",
            limit=self._policy.login_rate_limit,
            window_seconds=self._policy.login_rate_window_seconds,
        )
        if not decision.allowed:
            raise RateLimitedError(decision.retry_after_seconds)

        valid, _ = self._hasher.verify(current_password, user.hashed_password)
        if not valid:
            await self._audit_user(user, "auth.password_change_failed", client, reason="invalid_current_password")
            await self._uow.commit()
            # 422, not 401: a wrong current password must not look like an expired session to the console.
            raise ValidationFailedError(
                "Current password is incorrect",
                errors=[{"loc": ["current_password"], "msg": "is incorrect", "type": "invalid"}],
            )
        if new_password == current_password:
            raise ValidationFailedError(
                "Choose a new password",
                errors=[{"loc": ["new_password"], "msg": "must differ from the current password", "type": "same"}],
            )
        validate_password(new_password, email=user.email)

        now = self._clock()
        user.hashed_password = self._hasher.hash(new_password)
        await self._uow.users.update(user)
        revoked = await self._uow.refresh_tokens.revoke_all_for_user(user.id, now)
        if principal.token_jti and principal.token_expires_at:
            await self._blocklist.block(principal.token_jti, principal.token_expires_at)
        session = await self._open_session(user, family_id=uuid7(), now=now)
        await self._audit_user(user, "auth.password_changed", client, sessions_revoked=revoked)
        await self._uow.commit()
        AUTH_EVENTS.labels(event="password_change", outcome="success").inc()
        return session

    # --------------------------------------------------------------- helpers
    async def _open_session(self, user: User, *, family_id: UUID, now: datetime) -> AuthSession:
        plaintext = generate_opaque_token()
        expires_at = now + timedelta(seconds=self._policy.refresh_ttl_seconds)
        await self._uow.refresh_tokens.add(
            RefreshToken(
                id=uuid7(),
                org_id=user.org_id,
                user_id=user.id,
                family_id=family_id,
                token_hash=hash_opaque_token(plaintext),
                issued_at=now,
                expires_at=expires_at,
            )
        )
        access = self._access_tokens.issue(user_id=user.id, org_id=user.org_id, roles=tuple(sorted(user.role_names)))
        return AuthSession(user=user, access=access, refresh_token=plaintext, refresh_expires_at=expires_at)

    async def _audit_user(self, user: User, action: str, client: ClientInfo, **extra: Any) -> None:
        await self._uow.audit.record(
            AuditEvent(
                org_id=user.org_id,
                action=action,
                resource_type="user",
                resource_id=str(user.id),
                actor_id=user.id,
                context={**client.as_audit_context(), **extra},
            )
        )
