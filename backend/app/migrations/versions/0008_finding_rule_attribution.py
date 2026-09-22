"""Findings record who wrote the rule that fired and where it is published.

Community rules (SigmaHQ) are licensed on the condition that every match names their author, so the
attribution is stored with the finding rather than looked up from the current rule set: a finding stays
true to the rule text that fired, as `rule_version` already is.

Revision ID: 0008_finding_rule_attribution
Revises: 0007_incident_analyses
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_finding_rule_attribution"
down_revision: str | None = "0007_incident_analyses"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("rule_author", sa.String(255), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("rule_source", sa.String(1024), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "rule_source")
    op.drop_column("findings", "rule_author")
