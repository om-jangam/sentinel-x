from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db.base import Base, JsonType, UUIDPrimaryKeyMixin


class IncidentModel(UUIDPrimaryKeyMixin, Base):
    """Derived from its links by correlation; analysts change only status and resolution."""

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_org_id_last_seen", "org_id", "last_seen"),
        Index("ix_incidents_org_id_status", "org_id", "status"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    title: Mapped[str] = mapped_column(String(255))
    severity_id: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[str] = mapped_column(String(16))
    resolution: Mapped[str | None] = mapped_column(String(24))
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    techniques: Mapped[list[str]] = mapped_column(JsonType)
    tactics: Mapped[list[str]] = mapped_column(JsonType)
    assessment: Mapped[list[dict[str, Any]]] = mapped_column(JsonType)
    finding_count: Mapped[int] = mapped_column(Integer)
    event_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    closed_at: Mapped[datetime | None]
    version: Mapped[int] = mapped_column(Integer)


class IncidentLinkModel(UUIDPrimaryKeyMixin, Base):
    """Why a finding or event belongs to an incident. Written once, never updated."""

    __tablename__ = "incident_links"
    __table_args__ = (
        # A finding belongs to one incident; an event joins a given incident once.
        UniqueConstraint("org_id", "finding_id"),
        UniqueConstraint("incident_id", "event_uid"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    rule: Mapped[str] = mapped_column(String(48))
    reason: Mapped[str] = mapped_column(String(1024))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="RESTRICT"))
    event_uid: Mapped[str | None] = mapped_column(String(64))
    evidence: Mapped[list[str]] = mapped_column(JsonType)
    matched: Mapped[list[dict[str, Any]]] = mapped_column(JsonType)
    detail: Mapped[dict[str, Any]] = mapped_column(JsonType)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    created_at: Mapped[datetime]


class IncidentEntityModel(Base):
    """An entity seen in an incident's evidence, with the events it was seen in (capped)."""

    __tablename__ = "incident_entities"
    __table_args__ = (Index("ix_incident_entities_org_id_key", "org_id", "key"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(280))
    links: Mapped[bool] = mapped_column(Boolean)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    events: Mapped[list[str]] = mapped_column(JsonType)


class IncidentEventModel(Base):
    """A digest of one evidence event: the facts timelines and graphs are built from. Written once."""

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    time: Mapped[datetime]
    class_uid: Mapped[int] = mapped_column(Integer)
    activity_id: Mapped[int | None] = mapped_column(Integer)
    status_id: Mapped[int | None] = mapped_column(SmallInteger)
    action: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str | None] = mapped_column(String(16))
    message: Mapped[str | None] = mapped_column(String(512))
    raw: Mapped[str | None] = mapped_column(String(2048))
    roles: Mapped[dict[str, Any]] = mapped_column(JsonType)
    detail: Mapped[dict[str, Any]] = mapped_column(JsonType)


class IncidentNoteModel(UUIDPrimaryKeyMixin, Base):
    """Analyst notes: append-only, never updated or deleted through the application."""

    __tablename__ = "incident_notes"
    __table_args__ = (Index("ix_incident_notes_incident_id_created_at", "incident_id", "created_at"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    author_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    author_email: Mapped[str] = mapped_column(String(320))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime]
