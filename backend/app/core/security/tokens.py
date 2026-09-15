"""Access JWTs (PyJWT, RS256) and opaque refresh-token helpers (ADR-0010)."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt

from app.core.clock import Clock, utcnow
from app.core.errors import AuthenticationError
from app.core.ids import uuid7
from app.core.security.keys import KeyRing

ACCESS_TOKEN_TYPE = "at+jwt"  # noqa: S105 — RFC 9068 — stops other JWT kinds being replayed as access tokens
_ALGORITHM = "RS256"
_LEEWAY_SECONDS = 10


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    subject: UUID
    org_id: UUID
    roles: tuple[str, ...]
    jti: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    token: str
    jti: str
    expires_at: datetime
    expires_in: int


class AccessTokenService:
    def __init__(
        self,
        keyring: KeyRing,
        *,
        issuer: str,
        audience: str,
        ttl_seconds: int,
        clock: Clock = utcnow,
    ) -> None:
        self._keyring = keyring
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl_seconds
        self._clock = clock

    def issue(self, *, user_id: UUID, org_id: UUID, roles: tuple[str, ...]) -> IssuedAccessToken:
        issued_at = self._clock().replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=self._ttl)
        jti = str(uuid7())
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "org_id": str(org_id),
            "roles": list(roles),
            "jti": jti,
            "iat": int(issued_at.timestamp()),
            "nbf": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        token = jwt.encode(
            payload,
            self._keyring.signing_key,
            algorithm=_ALGORITHM,
            headers={"kid": self._keyring.signing_kid, "typ": ACCESS_TOKEN_TYPE},
        )
        return IssuedAccessToken(token=token, jti=jti, expires_at=expires_at, expires_in=self._ttl)

    def verify(self, token: str) -> AccessTokenClaims:
        invalid = AuthenticationError("Invalid access token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise invalid from exc
        if header.get("typ") != ACCESS_TOKEN_TYPE or header.get("alg") != _ALGORITHM:
            raise invalid
        kid = header.get("kid")
        key = self._keyring.verification_keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise invalid
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=[_ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("Access token expired") from exc
        except jwt.PyJWTError as exc:
            raise invalid from exc

        try:
            roles = payload.get("roles", [])
            if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
                raise ValueError("roles")
            return AccessTokenClaims(
                subject=UUID(payload["sub"]),
                org_id=UUID(payload["org_id"]),
                roles=tuple(roles),
                jti=str(payload["jti"]),
                issued_at=datetime.fromtimestamp(payload["iat"], UTC),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise invalid from exc


def generate_opaque_token() -> str:
    """256 bits of CSPRNG entropy."""
    return secrets.token_urlsafe(32)


def hash_opaque_token(token: str) -> str:
    """High-entropy secrets need a fast hash, not a password KDF: SHA-256 is correct here."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
