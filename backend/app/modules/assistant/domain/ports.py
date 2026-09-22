from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol
from uuid import UUID

from app.core.audit.port import AuditRecorder
from app.modules.assistant.domain.bundle import EvidenceBundle
from app.modules.assistant.domain.records import AnalysisRecord


class ModelUnavailableError(RuntimeError):
    """The model could not produce an answer: unreachable, timed out, or an error response."""


class LanguageModel(Protocol):
    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        """The raw reply text. Raises ModelUnavailableError when there is none."""
        ...

    async def aclose(self) -> None: ...


class BundleSource(Protocol):
    async def build(self, org_id: UUID, incident_id: UUID) -> EvidenceBundle | None:
        """The incident's evidence bundle, or None when the incident doesn't exist in this organisation."""
        ...


class AnalysisRepository(Protocol):
    async def add(self, record: AnalysisRecord) -> None: ...

    async def list_for_incident(self, org_id: UUID, incident_id: UUID) -> list[AnalysisRecord]: ...


class AssistantUnitOfWork(Protocol):
    @property
    def analyses(self) -> AnalysisRepository: ...

    @property
    def audit(self) -> AuditRecorder: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


UnitOfWorkFactory = Callable[[], AbstractAsyncContextManager[AssistantUnitOfWork]]
