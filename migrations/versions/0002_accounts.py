"""Add account, API-key and metadata-only usage tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_accounts"
down_revision: str | Sequence[str] | None = "0001_core_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("full_name", sa.String(length=256), nullable=False),
        sa.Column("organization", sa.String(length=256)),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("plan", sa.String(length=64), nullable=False, server_default="free"),
        sa.Column("requests_per_minute", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("requests_per_day", sa.Integer(), nullable=False, server_default="10000"),
        sa.Column("max_assets_per_request", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("signup_ip_hash", sa.String(length=128)),
        sa.Column("accepted_terms_version", sa.String(length=64)),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("environment", sa.String(length=8), nullable=False, server_default="live"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("label", sa.String(length=128)),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_table(
        "signup_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_signup_tokens_user_id", "signup_tokens", ["user_id"])
    op.create_index("ix_signup_tokens_token_hash", "signup_tokens", ["token_hash"], unique=True)
    op.create_table(
        "usage_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("key_id", sa.String(length=36), sa.ForeignKey("api_keys.id", ondelete="SET NULL")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("route", sa.String(length=256), nullable=False),
        sa.Column("query_params", sa.JSON(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("response_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("asset_count", sa.Integer()),
        sa.Column("mcp_tool_name", sa.String(length=128)),
        sa.Column("user_agent", sa.Text()),
        sa.Column("ip_hash", sa.String(length=128)),
    )
    op.create_index("ix_usage_logs_request_id", "usage_logs", ["request_id"])
    op.create_index("ix_usage_logs_user_id", "usage_logs", ["user_id"])
    op.create_index("ix_usage_logs_key_id", "usage_logs", ["key_id"])
    op.create_index("ix_usage_logs_timestamp", "usage_logs", ["timestamp"])
    op.create_table(
        "usage_daily_aggregates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("route", sa.String(length=256), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_response_size", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("day", "user_id", "route", name="uq_usage_daily_user_route"),
    )
    op.create_index("ix_usage_daily_aggregates_user_id", "usage_daily_aggregates", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_usage_daily_aggregates_user_id", table_name="usage_daily_aggregates")
    op.drop_table("usage_daily_aggregates")
    op.drop_index("ix_usage_logs_timestamp", table_name="usage_logs")
    op.drop_index("ix_usage_logs_key_id", table_name="usage_logs")
    op.drop_index("ix_usage_logs_user_id", table_name="usage_logs")
    op.drop_index("ix_usage_logs_request_id", table_name="usage_logs")
    op.drop_table("usage_logs")
    op.drop_index("ix_signup_tokens_token_hash", table_name="signup_tokens")
    op.drop_index("ix_signup_tokens_user_id", table_name="signup_tokens")
    op.drop_table("signup_tokens")
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
