"""Persist explicit closed-platform scope evidence for safe match fallbacks."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_closed_scope"
down_revision: str | Sequence[str] | None = "0003_range_default"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "advisories",
        sa.Column("closed_scopes", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("advisories", "closed_scopes")
