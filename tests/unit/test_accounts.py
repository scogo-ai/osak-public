from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from osak.accounts.models import APIKey, Base, UsageDailyAggregate, UsageLog
from osak.accounts.service import (
    authenticate_key,
    create_key,
    create_user,
    hash_api_key,
    issue_api_key,
    quota_status,
    reserve_usage,
    roll_up_usage,
    rotate_key,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    with maker() as db:
        yield db


def test_api_key_is_hmac_hashed_and_authentication_returns_owner(session):
    user = create_user(
        session,
        full_name="Ada Lovelace",
        organization="Analytical Engines",
        email="ada@example.com",
        verified=True,
        is_admin=False,
    )
    raw = issue_api_key(session, user, environment="test")

    stored = session.query(APIKey).one()
    assert raw.startswith("osak_test_")
    assert stored.key_hash == hash_api_key(raw)
    assert stored.key_hash != raw
    assert authenticate_key(session, raw).user_id == user.id
    assert authenticate_key(session, "osak_test_invalid") is None


def test_rotate_revokes_old_key_and_returns_new_plaintext(session):
    user = create_user(
        session,
        full_name="Grace Hopper",
        organization=None,
        email="grace@example.com",
        verified=True,
        is_admin=False,
    )
    old_raw = issue_api_key(session, user, environment="test")

    new_raw = rotate_key(session, user)

    assert new_raw.startswith("osak_test_")
    assert authenticate_key(session, old_raw) is None
    assert authenticate_key(session, new_raw).user_id == user.id
    assert session.query(APIKey).count() == 2


def test_create_key_prevents_two_active_keys_by_default(session):
    user = create_user(
        session,
        full_name="Alan Turing",
        organization=None,
        email="alan@example.com",
        verified=True,
        is_admin=False,
    )
    create_key(session, user, environment="test")

    with pytest.raises(ValueError, match="active key"):
        create_key(session, user, environment="test")


def test_usage_rows_keep_only_metadata(session):
    user = create_user(
        session,
        full_name="Dorothy Vaughan",
        organization=None,
        email="dorothy@example.com",
        verified=True,
        is_admin=False,
    )
    raw = issue_api_key(session, user, environment="test")
    key = authenticate_key(session, raw)

    from osak.accounts.service import record_usage

    record_usage(
        session,
        user=user,
        key=key,
        request_id="request-1",
        method="POST",
        route="/api/v1/match",
        status=200,
        latency_ms=12,
        response_size=42,
        asset_count=1,
        query_params={"vendor": "fortinet"},
        user_agent="pytest",
        ip_hash="hash",
    )
    row = session.query(UsageLog).one()
    assert row.route == "/api/v1/match"
    assert row.asset_count == 1
    assert not hasattr(row, "request_body")


def test_quota_reservation_counts_before_next_request(session):
    user = create_user(
        session,
        full_name="Mary Jackson",
        organization=None,
        email="mary@example.com",
        verified=True,
        is_admin=False,
        requests_per_minute=1,
    )
    raw = issue_api_key(session, user, environment="test")
    key = authenticate_key(session, raw)

    first, _ = reserve_usage(
        session,
        user=user,
        key=key,
        request_id="one",
        method="GET",
        route="/api/v1/me",
        query_params={},
        user_agent=None,
        ip_hash=None,
    )
    second, _ = reserve_usage(
        session,
        user=user,
        key=key,
        request_id="two",
        method="GET",
        route="/api/v1/me",
        query_params={},
        user_agent=None,
        ip_hash=None,
    )

    assert first.allowed is True
    assert second.allowed is False


def test_roll_up_usage_deletes_old_rows_and_keeps_daily_aggregate(session):
    user = create_user(
        session,
        full_name="Katherine Bouman",
        organization=None,
        email="kb@example.com",
        verified=True,
    )
    raw = issue_api_key(session, user, environment="test")
    key = authenticate_key(session, raw)
    from osak.accounts.service import record_usage

    record_usage(
        session,
        user=user,
        key=key,
        request_id="old",
        method="GET",
        route="/api/v1/me",
        status=200,
        latency_ms=10,
        response_size=20,
        query_params={},
        timestamp=datetime.now(UTC) - timedelta(days=91),
    )
    session.commit()

    deleted = roll_up_usage(session, now=datetime.now(UTC))
    session.commit()

    assert deleted == 1
    aggregate = session.query(UsageDailyAggregate).one()
    assert aggregate.request_count == 1
    assert aggregate.total_latency_ms == 10
    assert session.query(UsageLog).count() == 0


def test_production_rejects_test_keys_but_accepts_live_keys(session, monkeypatch):
    monkeypatch.setenv("OSAK_KEY_PEPPER", "production-test-pepper")
    user = create_user(
        session,
        full_name="Production User",
        organization=None,
        email="production@example.com",
        verified=True,
    )
    test_key = issue_api_key(session, user, environment="test")
    live_key = create_key(session, user, environment="live", allow_multiple=True)
    monkeypatch.setenv("OSAK_ENV", "production")

    assert authenticate_key(session, test_key) is None
    assert authenticate_key(session, live_key) is not None


def test_key_default_environment_follows_deployment(session, monkeypatch):
    monkeypatch.setenv("OSAK_KEY_PEPPER", "environment-test-pepper")
    user = create_user(
        session,
        full_name="Environment User",
        organization=None,
        email="environment@example.com",
        verified=True,
    )
    monkeypatch.setenv("OSAK_ENV", "production")
    production_key = issue_api_key(session, user)
    assert production_key.startswith("osak_live_")


def test_quota_reset_reports_oldest_window_expiry(session, monkeypatch):
    user = create_user(
        session,
        full_name="Quota User",
        organization=None,
        email="quota-reset@example.com",
        verified=True,
        requests_per_minute=1,
    )
    raw = issue_api_key(session, user, environment="test")
    key = authenticate_key(session, raw)
    from osak.accounts.service import record_usage

    now = datetime(2026, 1, 1, tzinfo=UTC)
    record_usage(
        session,
        user=user,
        key=key,
        request_id="quota-reset",
        method="GET",
        route="/api/v1/me",
        status=200,
        latency_ms=1,
        response_size=1,
        query_params={},
        timestamp=now - timedelta(seconds=50),
    )
    session.commit()

    quota = quota_status(session, user, key, now=now)

    assert quota.allowed is False
    assert 9 <= quota.reset_seconds <= 11

