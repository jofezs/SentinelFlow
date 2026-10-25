"""scan results columns and transactional outbox

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("scans", sa.Column("scanner", sa.String(64), nullable=True))
    op.add_column("scans", sa.Column("findings", _JSON, nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "max_severity",
            sa.Enum(*_SEVERITIES, name="severity", native_enum=False, length=32),
            nullable=True,
        ),
    )
    op.add_column("scans", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_outbox_events"),
    )
    op.create_index(
        "ix_outbox_events_unpublished",
        "outbox_events",
        ["created_at"],
        postgresql_where=sa.text("published_at IS NULL"),
        sqlite_where=sa.text("published_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_events_unpublished", table_name="outbox_events")
    op.drop_table("outbox_events")
    for column in ("completed_at", "error", "max_severity", "findings", "scanner"):
        op.drop_column("scans", column)
