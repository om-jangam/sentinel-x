"""Phase 2 detection: immutable findings that cite the events behind them.

Revision ID: 0003_findings
Revises: 0002_ingest_sources
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_findings"
down_revision: str | None = "0002_ingest_sources"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_title", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(16), nullable=False),
        sa.Column("rule_version", sa.String(64), nullable=False),
        sa.Column("severity_id", sa.SmallInteger(), nullable=False),
        sa.Column("tactics", JSON, nullable=False),
        sa.Column("entities", JSON, nullable=False),
        sa.Column("evidence", JSON, nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_findings_org_id_orgs", ondelete="RESTRICT"),
        sa.UniqueConstraint("org_id", "dedupe_key", name="uq_findings_org_id_dedupe_key"),
    )
    op.create_index("ix_findings_org_id_last_seen", "findings", ["org_id", "last_seen"])
    op.create_index("ix_findings_org_id_rule_id", "findings", ["org_id", "rule_id"])
    op.create_table(
        "finding_techniques",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.PrimaryKeyConstraint("finding_id", "technique_id", name="pk_finding_techniques"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_techniques_finding_id_findings",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_finding_techniques_technique_id", "finding_techniques", ["technique_id"])


def downgrade() -> None:
    op.drop_index("ix_finding_techniques_technique_id", table_name="finding_techniques")
    op.drop_table("finding_techniques")
    op.drop_index("ix_findings_org_id_rule_id", table_name="findings")
    op.drop_index("ix_findings_org_id_last_seen", table_name="findings")
    op.drop_table("findings")
