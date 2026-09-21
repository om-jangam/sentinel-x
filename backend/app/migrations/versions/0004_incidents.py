"""Phase 3 correlation: incidents, the links that justify their contents, and the entities they involve.

Revision ID: 0004_incidents
Revises: 0003_findings
Create Date: 2026-09-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_incidents"
down_revision: str | None = "0003_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity_id", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("resolution", sa.String(24), nullable=True),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("techniques", JSON, nullable=False),
        sa.Column("tactics", JSON, nullable=False),
        sa.Column("assessment", JSON, nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("closed_at", TS, nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_incidents"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_incidents_org_id_orgs", ondelete="RESTRICT"),
    )
    op.create_index("ix_incidents_org_id_last_seen", "incidents", ["org_id", "last_seen"])
    op.create_index("ix_incidents_org_id_status", "incidents", ["org_id", "status"])

    op.create_table(
        "incident_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("rule", sa.String(48), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column("event_uid", sa.String(64), nullable=True),
        sa.Column("evidence", JSON, nullable=False),
        sa.Column("matched", JSON, nullable=False),
        sa.Column("detail", JSON, nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_incident_links"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_incident_links_org_id_orgs", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_incident_links_incident_id_incidents", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_incident_links_finding_id_findings", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("org_id", "finding_id", name="uq_incident_links_org_id_finding_id"),
        sa.UniqueConstraint("incident_id", "event_uid", name="uq_incident_links_incident_id_event_uid"),
    )
    op.create_index("ix_incident_links_incident_id", "incident_links", ["incident_id"])

    op.create_table(
        "incident_entities",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(300), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(280), nullable=False),
        sa.Column("links", sa.Boolean(), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("events", JSON, nullable=False),
        sa.PrimaryKeyConstraint("incident_id", "key", name="pk_incident_entities"),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["incidents.id"], name="fk_incident_entities_incident_id_incidents", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name="fk_incident_entities_org_id_orgs", ondelete="RESTRICT"
        ),
    )
    op.create_index("ix_incident_entities_org_id_key", "incident_entities", ["org_id", "key"])


def downgrade() -> None:
    op.drop_index("ix_incident_entities_org_id_key", table_name="incident_entities")
    op.drop_table("incident_entities")
    op.drop_index("ix_incident_links_incident_id", table_name="incident_links")
    op.drop_table("incident_links")
    op.drop_index("ix_incidents_org_id_status", table_name="incidents")
    op.drop_index("ix_incidents_org_id_last_seen", table_name="incidents")
    op.drop_table("incidents")
