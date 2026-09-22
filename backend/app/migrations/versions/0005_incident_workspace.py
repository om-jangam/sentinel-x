"""Phase 4 workspace: evidence digests for timelines and graphs, and analyst notes.

Revision ID: 0005_incident_workspace
Revises: 0004_incidents
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_incident_workspace"
down_revision: str | None = "0004_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("event_uid", sa.String(64), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("time", TS, nullable=False),
        sa.Column("class_uid", sa.Integer(), nullable=False),
        sa.Column("activity_id", sa.Integer(), nullable=True),
        sa.Column("status_id", sa.SmallInteger(), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column("message", sa.String(512), nullable=True),
        sa.Column("raw", sa.String(2048), nullable=True),
        sa.Column("roles", JSON, nullable=False),
        sa.Column("detail", JSON, nullable=False),
        sa.PrimaryKeyConstraint("incident_id", "event_uid", name="pk_incident_events"),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_incident_events_incident_id_incidents", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_incident_events_org_id_orgs", ondelete="RESTRICT"),
    )
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        sa.Column("author_email", sa.String(320), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_incident_notes"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_incident_notes_org_id_orgs", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_incident_notes_incident_id_incidents", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["author_id"], ["users.id"], name="fk_incident_notes_author_id_users", ondelete="RESTRICT"
        ),
    )
    op.create_index("ix_incident_notes_incident_id_created_at", "incident_notes", ["incident_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_incident_notes_incident_id_created_at", table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_table("incident_events")
