"""Phase 1 ingestion: registered telemetry sources with their own revocable credentials.

Revision ID: 0002_ingest_sources
Revises: 0001_foundation
Create Date: 2026-09-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_ingest_sources"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "ingest_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("parser", sa.String(32), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("token_prefix", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("last_event_at", TS, nullable=True),
        sa.Column("events_accepted", sa.BigInteger(), nullable=False),
        sa.Column("events_rejected", sa.BigInteger(), nullable=False),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("last_error_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ingest_sources"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["orgs.id"],
            name="fk_ingest_sources_org_id_orgs",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("org_id", "name", name="uq_ingest_sources_org_id_name"),
        sa.UniqueConstraint("token_hash", name="uq_ingest_sources_token_hash"),
    )


def downgrade() -> None:
    op.drop_table("ingest_sources")
