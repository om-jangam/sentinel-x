from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

# A source that has sent nothing for this long is flagged: silent sources are a blind spot.
STALE_AFTER = timedelta(minutes=15)


class SourceHealth(StrEnum):
    HEALTHY = "healthy"
    STALE = "stale"
    ERRORING = "erroring"
    AWAITING_DATA = "awaiting_data"
    DISABLED = "disabled"


@dataclass(slots=True)
class IngestSource:
    """A registered telemetry producer with its own revocable credential and parser."""

    id: UUID
    org_id: UUID
    name: str
    description: str
    parser: str
    is_enabled: bool
    token_prefix: str
    token_hash: str
    created_at: datetime
    updated_at: datetime
    last_event_at: datetime | None = None
    events_accepted: int = 0
    events_rejected: int = 0
    last_error: str | None = None
    last_error_at: datetime | None = None

    def health(self, now: datetime) -> SourceHealth:
        if not self.is_enabled:
            return SourceHealth.DISABLED
        recent_error = self.last_error_at is not None and now - self.last_error_at < STALE_AFTER
        if recent_error and (self.last_event_at is None or self.last_error_at > self.last_event_at):  # type: ignore[operator]
            return SourceHealth.ERRORING
        if self.last_event_at is None:
            return SourceHealth.AWAITING_DATA
        if now - self.last_event_at > STALE_AFTER:
            return SourceHealth.STALE
        return SourceHealth.HEALTHY

    def audit_view(self) -> dict[str, Any]:
        """Never includes the token hash."""
        return {
            "name": self.name,
            "description": self.description,
            "parser": self.parser,
            "is_enabled": self.is_enabled,
            "token_prefix": self.token_prefix,
        }
