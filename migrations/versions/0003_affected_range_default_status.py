"""Retain explicit CNA defaults for version applicability fallbacks."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_range_default"
down_revision: str | Sequence[str] | None = "0002_accounts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("affected_ranges", sa.Column("default_status", sa.String(length=32)))


def downgrade() -> None:
    op.drop_column("affected_ranges", "default_status")
