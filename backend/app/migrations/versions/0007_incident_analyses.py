"""Phase 6 AI assistant: every analysis request, the evidence hash, and what survived validation.

Revision ID: 0007_incident_analyses
Revises: 0006_threat_intel
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_incident_analyses"
down_revision: str | None = "0006_threat_intel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "incident_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(32), nullable=False),
        sa.Column("bundle_hash", sa.String(64), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("output", JSON, nullable=True),
        sa.Column("dropped", JSON, nullable=False),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("citation_validity", sa.Float(), nullable=True),
        sa.Column("stats", JSON, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_incident_analyses"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_incident_analyses_org_id_orgs", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_incident_analyses_incident_id_incidents", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name="fk_incident_analyses_requested_by_users", ondelete="RESTRICT"
        ),
    )
    op.create_index(
        "ix_incident_analyses_incident_id_created_at", "incident_analyses", ["incident_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_incident_analyses_incident_id_created_at", table_name="incident_analyses")
    op.drop_table("incident_analyses")
