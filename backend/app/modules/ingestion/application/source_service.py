"""Ingest source registry: registration, credential rotation, enable/disable, authentication."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import AuthenticationError, ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import uuid7
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.core.security.tokens import hash_opaque_token
from app.ingest_pipeline.parsers import PARSERS
from app.modules.ingestion.domain.entities import IngestSource
from app.modules.ingestion.domain.policies import (
    INGEST_TOKEN_PREFIX,
    TOKEN_DISPLAY_LENGTH,
    validate_source_name,
)
from app.modules.ingestion.domain.ports import IngestionUnitOfWork


@dataclass(frozen=True, slots=True)
class CreateSourceCommand:
    name: str
    description: str
    parser: str


@dataclass(frozen=True, slots=True)
class IssuedSource:
    """The plaintext token is returned exactly once: at creation and at rotation."""

    source: IngestSource
    token: str


def _new_token() -> tuple[str, str, str]:
    token = INGEST_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, token[:TOKEN_DISPLAY_LENGTH], hash_opaque_token(token)


class SourceAdminService:
    def __init__(self, uow: IngestionUnitOfWork, *, clock: Clock = utcnow) -> None:
        self._uow = uow
        self._clock = clock

    async def list_sources(self, principal: Principal) -> list[IngestSource]:
        principal.require(Permission.SOURCE_READ)
        return await self._uow.sources.list_for_org(principal.org_id)

    async def get_source(self, principal: Principal, source_id: UUID) -> IngestSource:
        principal.require(Permission.SOURCE_READ)
        return await self._require(principal.org_id, source_id)

    async def create_source(self, principal: Principal, command: CreateSourceCommand) -> IssuedSource:
        principal.require(Permission.SOURCE_MANAGE)
        name = command.name.strip().lower()
        validate_source_name(name)
        if command.parser not in PARSERS:
            raise ValidationFailedError(
                "Unknown parser",
                errors=[
                    {
                        "loc": ["parser"],
                        "msg": f"must be one of: {', '.join(sorted(PARSERS))}",
                        "type": "unknown_parser",
                    }
                ],
            )
        if await self._uow.sources.name_exists(principal.org_id, name):
            raise ConflictError("A source with this name already exists")

        token, prefix, token_hash = _new_token()
        now = self._clock()
        source = IngestSource(
            id=uuid7(),
            org_id=principal.org_id,
            name=name,
            description=command.description.strip(),
            parser=command.parser,
            is_enabled=True,
            token_prefix=prefix,
            token_hash=token_hash,
            created_at=now,
            updated_at=now,
        )
        await self._uow.sources.add(source)
        await self._audit(principal, "ingest_source.created", source, after=source.audit_view())
        await self._uow.commit()
        return IssuedSource(source=source, token=token)

    async def rotate_token(self, principal: Principal, source_id: UUID) -> IssuedSource:
        principal.require(Permission.SOURCE_MANAGE)
        source = await self._require(principal.org_id, source_id)
        before = source.audit_view()
        token, prefix, token_hash = _new_token()
        source.token_prefix, source.token_hash = prefix, token_hash
        source.updated_at = self._clock()
        await self._uow.sources.update(source)
        await self._audit(principal, "ingest_source.token_rotated", source, before=before, after=source.audit_view())
        await self._uow.commit()
        return IssuedSource(source=source, token=token)

    async def set_enabled(self, principal: Principal, source_id: UUID, *, enabled: bool) -> IngestSource:
        principal.require(Permission.SOURCE_MANAGE)
        source = await self._require(principal.org_id, source_id)
        before = source.audit_view()
        source.is_enabled = enabled
        source.updated_at = self._clock()
        await self._uow.sources.update(source)
        action = "ingest_source.enabled" if enabled else "ingest_source.disabled"
        await self._audit(principal, action, source, before=before, after=source.audit_view())
        await self._uow.commit()
        return source

    async def authenticate(self, token: str) -> IngestSource:
        """Resolve a source ingest token. Disabled sources authenticate but cannot ingest."""
        source = await self._uow.sources.get_by_token_hash(hash_opaque_token(token))
        if source is None:
            raise AuthenticationError("Invalid ingest token")
        return source

    async def _require(self, org_id: UUID, source_id: UUID) -> IngestSource:
        source = await self._uow.sources.get(org_id, source_id)
        if source is None:
            raise NotFoundError("Ingest source not found")
        return source

    async def _audit(
        self,
        principal: Principal,
        action: str,
        source: IngestSource,
        *,
        before: dict[str, object] | None = None,
        after: dict[str, object] | None = None,
    ) -> None:
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action=action,
                resource_type="ingest_source",
                resource_id=str(source.id),
                actor_id=principal.user_id,
                before=before,
                after=after,
            )
        )
