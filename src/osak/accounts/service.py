"""Synchronous account and API-key operations.

These functions intentionally accept a caller-owned SQLAlchemy session.  The
API and CLI can therefore share the exact same persistence semantics while
tests use an in-memory SQLite database.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from osak.accounts.models import APIKey, UsageDailyAggregate, UsageLog, User

DEFAULT_RPM = 60
DEFAULT_RPD = 10_000


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _pepper() -> str:
    value = os.getenv("OSAK_KEY_PEPPER")
    if value:
        return value
    if os.getenv("OSAK_ENV", "development").lower() in {"production", "prod"}:
        raise RuntimeError("OSAK_KEY_PEPPER must be configured in production")
    return "osak-development-only-pepper"


def _hmac(value: str) -> str:
    return hmac.new(_pepper().encode(), value.encode(), hashlib.sha256).hexdigest()


def hash_api_key(raw_key: str) -> str:
    """Return the HMAC-SHA256 digest stored for an API key."""

    return _hmac(raw_key)


def hash_ip(ip: str | None) -> str | None:
    """Hash a client address before it enters an account or usage row."""

    if not ip:
        return None
    return _hmac(f"ip:{ip}")


def hash_user_agent(user_agent: str | None) -> str | None:
    """Store a stable digest instead of caller-controlled user-agent text."""

    if not user_agent:
        return None
    if user_agent.startswith("sha256:") and len(user_agent) == len("sha256:") + 64:
        return user_agent
    return f"sha256:{hashlib.sha256(user_agent.encode('utf-8', 'replace')).hexdigest()}"


def _environment(environment: str | None = None) -> str:
    selected = environment or ("live" if _is_production() else "test")
    if selected not in {"live", "test"}:
        raise ValueError("environment must be live or test")
    if _is_production() and selected == "test":
        raise ValueError("test keys are disabled in production")
    return selected


def _is_production() -> bool:
    return os.getenv("OSAK_ENV", "development").lower() in {"production", "prod"}


def _new_key(environment: str) -> str:
    return f"osak_{environment}_{secrets.token_urlsafe(32)}"


def create_user(
    session: Session,
    *,
    full_name: str,
    organization: str | None,
    email: str,
    verified: bool = False,
    is_admin: bool = False,
    status: str | None = None,
    signup_ip_hash: str | None = None,
    accepted_terms_version: str | None = None,
    requests_per_minute: int = DEFAULT_RPM,
    requests_per_day: int = DEFAULT_RPD,
    max_assets_per_request: int = 500,
) -> User:
    """Create a normalized account without committing the caller's transaction."""

    if not 1 <= requests_per_minute <= 1_000_000:
        raise ValueError("requests_per_minute must be between 1 and 1000000")
    if not 1 <= requests_per_day <= 10_000_000:
        raise ValueError("requests_per_day must be between 1 and 10000000")
    if not 1 <= max_assets_per_request <= 100_000:
        raise ValueError("max_assets_per_request must be between 1 and 100000")
    normalized_email = email.strip().lower()
    if session.query(User).filter(func.lower(User.email) == normalized_email).first():
        raise ValueError("email already registered")
    user = User(
        full_name=full_name.strip(),
        organization=organization.strip() if organization else None,
        email=normalized_email,
        email_verified=verified,
        status=status or ("active" if verified else "pending"),
        is_admin=is_admin,
        signup_ip_hash=signup_ip_hash,
        accepted_terms_version=accepted_terms_version,
        requests_per_minute=requests_per_minute,
        requests_per_day=requests_per_day,
        max_assets_per_request=max_assets_per_request,
    )
    session.add(user)
    session.flush()
    return user


def create_key(
    session: Session,
    user: User,
    *,
    environment: str | None = None,
    label: str | None = None,
    allow_multiple: bool = False,
) -> str:
    """Create a key and return its plaintext exactly once."""

    selected_environment = _environment(environment)
    # Lock the owning account while checking the active-key invariant. This
    # serializes concurrent rotations/issuance on PostgreSQL.
    session.query(User).filter(User.id == user.id).with_for_update().one()
    active = (
        session.query(APIKey)
        .filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None))
        .first()
    )
    if active and not allow_multiple:
        raise ValueError("user already has an active key")
    raw_key = _new_key(selected_environment)
    store_api_key(session, user, raw_key, label=label, allow_multiple=allow_multiple)
    return raw_key


def store_api_key(
    session: Session,
    user: User,
    raw_key: str,
    *,
    label: str | None = None,
    allow_multiple: bool = False,
) -> APIKey:
    """Persist an already-issued plaintext key without storing that plaintext."""

    if raw_key.startswith("osak_live_"):
        environment = "live"
    elif raw_key.startswith("osak_test_"):
        environment = "test"
    else:
        raise ValueError("invalid OSAK API key")
    _environment(environment)
    session.query(User).filter(User.id == user.id).with_for_update().one()
    existing = session.query(APIKey).filter(APIKey.key_hash == hash_api_key(raw_key)).first()
    if existing is not None:
        return existing
    active = (
        session.query(APIKey)
        .filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None))
        .first()
    )
    if active and not allow_multiple:
        raise ValueError("user already has an active key")
    session.add(
        APIKey(
            user_id=user.id,
            prefix=raw_key[:18],
            key_hash=hash_api_key(raw_key),
            environment=environment,
            label=label,
        )
    )
    session.flush()
    return session.query(APIKey).filter(APIKey.key_hash == hash_api_key(raw_key)).one()


def issue_api_key(session: Session, user: User, *, environment: str | None = None) -> str:
    return create_key(session, user, environment=environment)


def authenticate_key(session: Session, raw_key: str | None) -> APIKey | None:
    """Resolve a raw key without exposing whether a prefix belongs to a user."""

    if not raw_key or not raw_key.startswith(("osak_live_", "osak_test_")):
        return None
    if _is_production() and raw_key.startswith("osak_test_"):
        return None
    key = (
        session.query(APIKey)
        .filter(APIKey.key_hash == hash_api_key(raw_key), APIKey.revoked_at.is_(None))
        .first()
    )
    if key is None or key.user is None or key.user.status != "active":
        return None
    key.last_used_at = datetime.now(UTC)
    session.flush()
    return key


def revoke_key(session: Session, key: APIKey) -> None:
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        session.flush()


def rotate_key(session: Session, user: User, *, environment: str | None = None) -> str:
    """Revoke every active key for a user, then issue one replacement."""

    for key in session.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None)):
        revoke_key(session, key)
    return create_key(session, user, environment=environment, allow_multiple=True)


@dataclass(frozen=True)
class QuotaStatus:
    allowed: bool
    per_minute_limit: int
    per_day_limit: int
    minute_count: int
    day_count: int
    reset_seconds: int

    @property
    def remaining(self) -> int:
        return max(0, min(self.per_minute_limit - self.minute_count, self.per_day_limit - self.day_count))


def quota_status(session: Session, user: User, key: APIKey, *, now: datetime | None = None) -> QuotaStatus:
    current = _now(now)
    minute_start = current - timedelta(minutes=1)
    day_start = current - timedelta(days=1)
    minute_count = (
        session.query(func.count(UsageLog.id))
        .filter(UsageLog.key_id == key.id, UsageLog.timestamp >= minute_start)
        .scalar()
        or 0
    )
    day_count = (
        session.query(func.count(UsageLog.id))
        .filter(UsageLog.key_id == key.id, UsageLog.timestamp >= day_start)
        .scalar()
        or 0
    )
    oldest_minute = (
        session.query(func.min(UsageLog.timestamp))
        .filter(UsageLog.key_id == key.id, UsageLog.timestamp >= minute_start)
        .scalar()
    )
    oldest_day = (
        session.query(func.min(UsageLog.timestamp))
        .filter(UsageLog.key_id == key.id, UsageLog.timestamp >= day_start)
        .scalar()
    )

    def reset_after(oldest: datetime | None, window: timedelta) -> int:
        if oldest is None:
            return max(1, math.ceil(window.total_seconds()))
        return max(1, math.ceil((_now(oldest) + window - current).total_seconds()))

    minute_reset = reset_after(oldest_minute, timedelta(minutes=1))
    day_reset = reset_after(oldest_day, timedelta(days=1))
    reset_seconds = minute_reset if minute_count >= user.requests_per_minute else day_reset
    return QuotaStatus(
        allowed=minute_count < user.requests_per_minute and day_count < user.requests_per_day,
        per_minute_limit=user.requests_per_minute,
        per_day_limit=user.requests_per_day,
        minute_count=int(minute_count),
        day_count=int(day_count),
        reset_seconds=reset_seconds,
    )


def record_usage(
    session: Session,
    *,
    user: User | None,
    key: APIKey | None,
    request_id: str,
    method: str,
    route: str,
    status: int,
    latency_ms: int,
    response_size: int,
    query_params: dict[str, str],
    asset_count: int | None = None,
    mcp_tool_name: str | None = None,
    user_agent: str | None = None,
    ip_hash: str | None = None,
    timestamp: datetime | None = None,
) -> UsageLog:
    """Persist only the allow-listed request metadata required for quotas."""

    row = UsageLog(
        request_id=request_id,
        user_id=user.id if user else None,
        key_id=key.id if key else None,
        timestamp=_now(timestamp),
        method=method[:16],
        route=route[:256],
        query_params={key: query_params[key] for key in ("vendor", "product", "severity", "since") if key in query_params},
        status=status,
        latency_ms=max(0, int(latency_ms)),
        response_size=max(0, int(response_size)),
        asset_count=asset_count,
        mcp_tool_name=mcp_tool_name,
        user_agent=hash_user_agent(user_agent),
        ip_hash=ip_hash,
    )
    session.add(row)
    session.flush()
    return row


def reserve_usage(
    session: Session,
    *,
    user: User,
    key: APIKey,
    request_id: str,
    method: str,
    route: str,
    query_params: dict[str, str],
    user_agent: str | None,
    ip_hash: str | None,
    now: datetime | None = None,
) -> tuple[QuotaStatus, UsageLog]:
    """Atomically check a quota and reserve this request's usage slot.

    PostgreSQL locks the key row for the count-and-insert transaction, so two
    concurrent requests cannot both pass the same boundary.  SQLite ignores
    ``FOR UPDATE`` but remains deterministic for local development.
    """

    locked_key = (
        session.query(APIKey)
        .filter(APIKey.id == key.id, APIKey.revoked_at.is_(None))
        .with_for_update()
        .one()
    )
    quota = quota_status(session, user, locked_key, now=now)
    row = record_usage(
        session,
        user=user,
        key=locked_key,
        request_id=request_id,
        method=method,
        route=route,
        status=0,
        latency_ms=0,
        response_size=0,
        query_params=query_params,
        user_agent=user_agent,
        ip_hash=ip_hash,
        timestamp=now,
    )
    session.commit()
    return quota, row


def finalize_usage(
    session: Session,
    usage_id: int,
    *,
    status: int,
    latency_ms: int,
    response_size: int,
    asset_count: int | None,
    mcp_tool_name: str | None = None,
) -> UsageLog | None:
    """Fill the response metadata on a previously reserved usage row."""

    row = session.get(UsageLog, usage_id)
    if row is None:
        return None
    row.status = status
    row.latency_ms = max(0, int(latency_ms))
    row.response_size = max(0, int(response_size))
    row.asset_count = asset_count
    row.mcp_tool_name = mcp_tool_name
    session.flush()
    return row


def roll_up_usage(
    session: Session,
    *,
    now: datetime | None = None,
    retention_days: int = 90,
) -> int:
    """Roll up detailed request metadata older than *retention_days* and delete it."""

    if retention_days < 1:
        raise ValueError("retention_days must be positive")
    cutoff = _now(now) - timedelta(days=retention_days)
    rows = (
        session.query(UsageLog)
        .filter(UsageLog.timestamp < cutoff, UsageLog.user_id.is_not(None))
        .all()
    )
    buckets: dict[tuple[Any, str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for row in rows:
        bucket = buckets[(row.timestamp.date(), row.user_id, row.route)]
        bucket[0] += 1
        bucket[1] += int(row.status >= 400 or row.status == 0)
        bucket[2] += row.latency_ms
        bucket[3] += row.response_size
    for (day, user_id, route), values in buckets.items():
        aggregate = (
            session.query(UsageDailyAggregate)
            .filter(
                UsageDailyAggregate.day == day,
                UsageDailyAggregate.user_id == user_id,
                UsageDailyAggregate.route == route,
            )
            .first()
        )
        if aggregate is None:
            aggregate = UsageDailyAggregate(
                day=day,
                user_id=user_id,
                route=route,
                request_count=0,
                error_count=0,
                total_latency_ms=0,
                total_response_size=0,
            )
            session.add(aggregate)
        aggregate.request_count += values[0]
        aggregate.error_count += values[1]
        aggregate.total_latency_ms += values[2]
        aggregate.total_response_size += values[3]
    for row in rows:
        session.delete(row)
    session.flush()
    return len(rows)


__all__ = [
    "DEFAULT_RPD",
    "DEFAULT_RPM",
    "QuotaStatus",
    "authenticate_key",
    "create_key",
    "create_user",
    "finalize_usage",
    "hash_api_key",
    "hash_ip",
    "hash_user_agent",
    "issue_api_key",
    "quota_status",
    "record_usage",
    "reserve_usage",
    "revoke_key",
    "roll_up_usage",
    "rotate_key",
    "store_api_key",
]
