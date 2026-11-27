"""Persist complete supported hardware sets by product release."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_supported_platforms"
down_revision: str | Sequence[str] | None = "0004_closed_scope"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "products",
        sa.Column("supported_platforms_by_release", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("products", "supported_platforms_by_release")
