"""Phase 5 threat intelligence: the cached answer of each provider about each indicator, per organisation.

Revision ID: 0006_threat_intel
Revises: 0005_incident_workspace
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_threat_intel"
down_revision: str | None = "0005_incident_workspace"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "intel_results",
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("indicator_type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("confidence", sa.SmallInteger(), nullable=True),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("tags", JSON, nullable=False),
        sa.Column("related", JSON, nullable=False),
        sa.Column("references", JSON, nullable=False),
        sa.Column("provider_first_seen", TS, nullable=True),
        sa.Column("provider_last_seen", TS, nullable=True),
        sa.Column("retrieved_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("error", sa.String(200), nullable=True),
        sa.PrimaryKeyConstraint("org_id", "provider", "indicator_type", "value", name="pk_intel_results"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_intel_results_org_id_orgs", ondelete="RESTRICT"),
    )


def downgrade() -> None:
    op.drop_table("intel_results")
