from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, SmallInteger, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db.base import Base, JsonType, UUIDPrimaryKeyMixin


class FindingModel(UUIDPrimaryKeyMixin, Base):
    """A detection result and the events that support it. Written once, never updated."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("org_id", "dedupe_key"),
        Index("ix_findings_org_id_last_seen", "org_id", "last_seen"),
        Index("ix_findings_org_id_rule_id", "org_id", "rule_id"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_title: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(16))
    rule_version: Mapped[str] = mapped_column(String(64))
    severity_id: Mapped[int] = mapped_column(SmallInteger)
    tactics: Mapped[list[str]] = mapped_column(JsonType)
    entities: Mapped[dict[str, Any]] = mapped_column(JsonType)
    evidence: Mapped[list[str]] = mapped_column(JsonType)
    evidence_count: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    dedupe_key: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime]

    techniques: Mapped[list[FindingTechniqueModel]] = relationship(
        lazy="selectin", cascade="all, delete-orphan", order_by="FindingTechniqueModel.technique_id"
    )


class FindingTechniqueModel(Base):
    """One row per ATT&CK technique, so findings can be filtered and counted by technique portably."""

    __tablename__ = "finding_techniques"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True, index=True)
