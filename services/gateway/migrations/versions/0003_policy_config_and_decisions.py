"""project policy config and scan policy decisions

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("projects", sa.Column("policy_config", _JSON, nullable=True))
    op.add_column("scans", sa.Column("policy_passed", sa.Boolean(), nullable=True))
    op.add_column("scans", sa.Column("policy_violations", _JSON, nullable=True))
    op.add_column(
        "scans", sa.Column("policy_evaluated_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "policy_evaluated_at")
    op.drop_column("scans", "policy_violations")
    op.drop_column("scans", "policy_passed")
    op.drop_column("projects", "policy_config")
