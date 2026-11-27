"""Track one-time signup key delivery without storing key material."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_single_submit_signup"
down_revision: str | Sequence[str] | None = "0005_supported_platforms"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("signup_key_sent_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("users", "signup_key_sent_at")
