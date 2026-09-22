from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, SmallInteger, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db.base import Base, JsonType


class IntelResultModel(Base):
    """The latest answer from one provider about one indicator, per organisation, with when it was asked."""

    __tablename__ = "intel_results"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    summary: Mapped[str] = mapped_column(String(500))
    tags: Mapped[list[str]] = mapped_column(JsonType)
    related: Mapped[list[dict[str, Any]]] = mapped_column(JsonType)
    references: Mapped[list[str]] = mapped_column(JsonType)
    provider_first_seen: Mapped[datetime | None]
    provider_last_seen: Mapped[datetime | None]
    retrieved_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    error: Mapped[str | None] = mapped_column(String(200))
