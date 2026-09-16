from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IngestSourceModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A registered telemetry producer. The token hash is the credential; the plaintext is never stored."""

    __tablename__ = "ingest_sources"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), default="")
    parser: Mapped[str] = mapped_column(String(32))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)

    # Health and throughput bookkeeping, updated with atomic increments per batch.
    last_event_at: Mapped[datetime | None] = mapped_column(default=None)
    events_accepted: Mapped[int] = mapped_column(BigInteger, default=0)
    events_rejected: Mapped[int] = mapped_column(BigInteger, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), default=None)
    last_error_at: Mapped[datetime | None] = mapped_column(default=None)
