from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.audit.chain import ChainEntry
from app.core.db.base import Base, JsonType, UUIDPrimaryKeyMixin


class AuditLogModel(UUIDPrimaryKeyMixin, Base):
    """Append-only, hash-chained audit trail. UPDATE/DELETE are blocked by a Postgres trigger.

    No foreign keys by design: audit history must outlive (and never block deletion of) the
    rows it describes.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("org_id", "chain_index"),
        Index("ix_audit_log_org_id_ts", "org_id", "ts"),
        Index("ix_audit_log_org_id_action", "org_id", "action"),
    )

    org_id: Mapped[uuid.UUID]
    chain_index: Mapped[int] = mapped_column(BigInteger)
    ts: Mapped[datetime]
    actor_id: Mapped[uuid.UUID | None]
    actor_type: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    before: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    after: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    context: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    correlation_id: Mapped[str | None] = mapped_column(String(128))
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)

    def to_chain_entry(self) -> ChainEntry:
        return ChainEntry(
            org_id=self.org_id,
            chain_index=self.chain_index,
            ts=self.ts,
            actor_id=self.actor_id,
            actor_type=self.actor_type,
            action=self.action,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            before=self.before,
            after=self.after,
            context=self.context,
            correlation_id=self.correlation_id,
        )
