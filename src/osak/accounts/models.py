"""SQLAlchemy persistence models owned by the accounts workstream.

The application core owns the declarative base; accounts only declares its
tables against ``osak.core.db.Base``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from osak.core.db import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class User(Base):  # type: ignore[misc,valid-type]
    """An OSAK account, including its quota and admin status."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=new_id)
    full_name = Column(String(256), nullable=False)
    organization = Column(String(256), nullable=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    status = Column(String(32), nullable=False, default="pending")
    plan = Column(String(64), nullable=False, default="free")
    requests_per_minute = Column(Integer, nullable=False, default=60)
    requests_per_day = Column(Integer, nullable=False, default=10_000)
    max_assets_per_request = Column(Integer, nullable=False, default=500)
    signup_ip_hash = Column(String(128), nullable=True)
    accepted_terms_version = Column(String(64), nullable=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    signup_key_sent_at = Column(DateTime(timezone=True), nullable=True)

    keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    usage = relationship("UsageLog", back_populates="user", cascade="all, delete-orphan")


class APIKey(Base):  # type: ignore[misc,valid-type]
    """A peppered API-key record; ``plaintext`` is never a model field."""

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=new_id)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    prefix = Column(String(32), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    environment = Column(String(8), nullable=False, default="live")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    label = Column(String(128), nullable=True)

    user = relationship("User", back_populates="keys")
    usage = relationship("UsageLog", back_populates="key", cascade="all, delete-orphan")


class _RetiredSignupToken(Base):  # type: ignore[misc,valid-type]
    """Schema used by the previous rollback image. The signup handler never accesses it."""

    __tablename__ = "signup_tokens"

    id = Column(String(36), primary_key=True, default=new_id)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


class UsageLog(Base):  # type: ignore[misc,valid-type]
    """Allow-listed request metadata only; never add request-body columns."""

    __tablename__ = "usage_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    key_id = Column(String(36), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    method = Column(String(16), nullable=False)
    route = Column(String(256), nullable=False)
    query_params = Column(JSON, nullable=False, default=dict)
    status = Column(Integer, nullable=False)
    latency_ms = Column(Integer, nullable=False, default=0)
    response_size = Column(Integer, nullable=False, default=0)
    asset_count = Column(Integer, nullable=True)
    mcp_tool_name = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
    ip_hash = Column(String(128), nullable=True)

    user = relationship("User", back_populates="usage")
    key = relationship("APIKey", back_populates="usage")


class UsageDailyAggregate(Base):  # type: ignore[misc,valid-type]
    """Daily metadata aggregate retained after detailed rows expire."""

    __tablename__ = "usage_daily_aggregates"
    __table_args__ = (UniqueConstraint("day", "user_id", "route", name="uq_usage_daily_user_route"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    day = Column(Date, nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    route = Column(String(256), nullable=False)
    request_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    total_latency_ms = Column(Integer, nullable=False, default=0)
    total_response_size = Column(Integer, nullable=False, default=0)


def model_columns(model: type[Any]) -> set[str]:
    """Return mapped column names, useful to keep migration adapters narrow."""

    return {column.name for column in model.__table__.columns}


__all__ = [
    "APIKey",
    "Base",
    "UsageDailyAggregate",
    "UsageLog",
    "User",
    "model_columns",
]
