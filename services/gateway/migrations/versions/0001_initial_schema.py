"""initial schema: projects, api_keys, scans

Revision ID: 0001
Revises:
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TARGET_TYPES = ("image", "dockerfile", "api_endpoint")
_SCAN_STATES = ("queued", "running", "completed", "failed")


def _varchar_enum(values: tuple[str, ...], name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32)


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(63), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
        sa.UniqueConstraint("name", name="uq_projects_name"),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_api_keys_project_id_projects",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("prefix", name="uq_api_keys_prefix"),
    )
    op.create_index("ix_api_keys_project_id", "api_keys", ["project_id"])
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", _varchar_enum(_TARGET_TYPES, "targettype"), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("status", _varchar_enum(_SCAN_STATES, "scanstate"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_scans_project_id_projects",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_project_id_created_at", "scans", ["project_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_project_id_created_at", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_api_keys_project_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("projects")
