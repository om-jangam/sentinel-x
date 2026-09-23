"""What an organisation has seen before: counts per process pair and external destination.

Context for investigation, not detection. One row per organisation, kind and key, with the first and last
time it was seen and how often. No time series: a count answers "has this ever happened here?", which is
what novelty needs, and keeps one row per key rather than one per sighting.

Revision ID: 0009_entity_baselines
Revises: 0008_finding_rule_attribution
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_entity_baselines"
down_revision: str | None = "0008_finding_rule_attribution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "entity_baselines",
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("key", sa.String(280), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("observations", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("org_id", "kind", "key", name="pk_entity_baselines"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_entity_baselines_org_id_orgs", ondelete="RESTRICT"),
    )
    op.create_index("ix_entity_baselines_org_id_last_seen", "entity_baselines", ["org_id", "last_seen"])


def downgrade() -> None:
    op.drop_index("ix_entity_baselines_org_id_last_seen", table_name="entity_baselines")
    op.drop_table("entity_baselines")
