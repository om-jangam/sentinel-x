"""Phase 0 foundation: orgs, RBAC, users, refresh tokens, tamper-evident audit log.

Revision ID: 0001_foundation
Revises:
Create Date: 2026-09-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_orgs"),
        sa.UniqueConstraint("slug", name="uq_orgs_slug"),
    )
    op.create_table(
        "permissions",
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint("name", name="pk_permissions"),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_roles_org_id_orgs", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("org_id", "name", name="uq_roles_org_id_name"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_users_org_id_orgs", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_org_id_id", "users", ["org_id", "id"])
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], name="fk_user_roles_role_id_roles", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_user_roles_user_id_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_name", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_name"],
            ["permissions.name"],
            name="fk_role_permissions_permission_name_permissions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], name="fk_role_permissions_role_id_roles", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("role_id", "permission_name", name="pk_role_permissions"),
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], name="fk_refresh_tokens_org_id_orgs", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_refresh_tokens_user_id_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("chain_index", sa.BigInteger(), nullable=False),
        sa.Column("ts", TS, nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("before", JSON, nullable=True),
        sa.Column("after", JSON, nullable=True),
        sa.Column("context", JSON, nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
        sa.UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        sa.UniqueConstraint("org_id", "chain_index", name="uq_audit_log_org_id_chain_index"),
    )
    op.create_index("ix_audit_log_org_id_ts", "audit_log", ["org_id", "ts"])
    op.create_index("ix_audit_log_org_id_action", "audit_log", ["org_id", "action"])

    if op.get_bind().dialect.name == "postgresql":
        # Defence in depth beyond the hash chain: the application role cannot rewrite history.
        op.execute(
            """
            CREATE FUNCTION audit_log_block_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP
                    USING ERRCODE = 'insufficient_privilege';
            END;
            $$;
            """
        )
        op.execute(
            """
            CREATE TRIGGER audit_log_append_only
            BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
            FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();
            """
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS audit_log_block_mutation()")
    op.drop_table("audit_log")
    op.drop_table("refresh_tokens")
    op.drop_table("role_permissions")
    op.drop_table("user_roles")
    op.drop_table("users")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.drop_table("orgs")
