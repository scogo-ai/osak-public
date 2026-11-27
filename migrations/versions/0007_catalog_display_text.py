"""Widen canonical display labels for source-provided product names."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_catalog_display_text"
down_revision: str | Sequence[str] | None = "0006_single_submit_signup"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return
    for table, column, existing_length in (
        ("vendors", "name", 512),
        ("products", "family", 512),
        ("products", "os", 256),
    ):
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length=existing_length),
            type_=sa.Text(),
            existing_nullable=False,
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return
    for table, column, length in (
        ("vendors", "name", 512),
        ("products", "family", 512),
        ("products", "os", 256),
    ):
        op.alter_column(
            table,
            column,
            existing_type=sa.Text(),
            type_=sa.String(length=length),
            existing_nullable=False,
        )
