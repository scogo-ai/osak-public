from __future__ import annotations

from importlib import import_module

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

app_module = import_module("osak.api.app")
from osak.accounts.models import Base, UsageLog
from osak.accounts.service import create_user, issue_api_key


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(app_module, "SessionLocal", factory)
    monkeypatch.setattr(app_module.core_repository, "list_source_sync_states", lambda session: [])
    monkeypatch.setenv("OSAK_ENV", "test")
    with factory() as session:
        user = create_user(
            session,
            full_name="Test User",
            organization="OSAK",
            email="test@example.com",
            verified=True,
        )
        raw_key = issue_api_key(session, user, environment="test")
        session.commit()
    with TestClient(app_module.app) as test_client:
        yield test_client, raw_key, factory


def test_health_is_public(client):
    test_client, _, _ = client

    response = test_client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_match_requires_api_key(client):
    test_client, _, _ = client

    response = test_client.post(
        "/api/v1/match",
        json={"assets": [{"asset_ref": "a", "vendor": "fortinet", "version": "7.2.5"}]},
    )

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")


def test_match_redacts_inventory_from_usage_and_logs(client, monkeypatch, caplog):
    test_client, raw_key, factory = client
    canary = "CANARY-DO-NOT-STORE-6c9b3b"

    def fake_match(dataset, request):
        return {"results": [{"asset_ref": request.assets[0].asset_ref, "status": "unresolved", "findings": []}]}

    monkeypatch.setattr(app_module, "inventory_match_request", lambda session, request: fake_match(None, request))
    response = test_client.post(
        "/api/v1/match",
        headers={"X-API-Key": raw_key},
        json={
            "assets": [
                {"asset_ref": canary, "vendor": "fortinet", "version": "7.2.5"}
            ]
        },
    )

    assert response.status_code == 200
    assert canary not in caplog.text
    with factory() as session:
        assert canary not in " ".join(str(row.__dict__) for row in session.query(UsageLog).all())


def test_match_internal_error_does_not_echo_inventory(client, monkeypatch, caplog):
    test_client, raw_key, factory = client
    canary = "CANARY-INTERNAL-ERROR-DO-NOT-STORE"

    def failed_match(session, request):
        raise RuntimeError(canary)

    monkeypatch.setattr(app_module, "inventory_match_request", failed_match)
    response = test_client.post(
        "/api/v1/match",
        headers={"X-API-Key": raw_key},
        json={"assets": [{"asset_ref": canary, "vendor": "fortinet", "version": "7.2.5"}]},
    )

    assert response.status_code == 500
    assert canary not in response.text
    assert canary not in caplog.text
    with factory() as session:
        assert canary not in " ".join(str(row.__dict__) for row in session.query(UsageLog).all())


def test_match_rejects_more_than_500_assets(client):
    test_client, raw_key, _ = client
    assets = [
        {"asset_ref": str(index), "vendor": "fortinet", "version": "7.2.5"}
        for index in range(501)
    ]

    response = test_client.post("/api/v1/match", headers={"X-API-Key": raw_key}, json={"assets": assets})

    assert response.status_code == 422
    assert "500" in response.text


def test_authenticated_response_has_rate_limit_headers(client, monkeypatch):
    test_client, raw_key, _ = client
    monkeypatch.setattr(app_module, "inventory_match_request", lambda session, request: {"results": []})

    response = test_client.post(
        "/api/v1/match",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"assets": [{"asset_ref": "a", "vendor": "fortinet", "version": "7.2.5"}]},
    )

    assert response.status_code == 200
    assert response.headers["ratelimit-limit"] == "60"
    assert response.headers["ratelimit-remaining"] == "59"


def test_quota_rejection_preserves_rate_limit_headers(client, monkeypatch):
    test_client, raw_key, factory = client
    monkeypatch.setattr(app_module, "inventory_match_request", lambda session, request: {"results": []})
    with factory() as session:
        from osak.accounts.models import User

        user = session.query(User).filter(User.email == "test@example.com").one()
        user.requests_per_minute = 1
        session.commit()
    payload = {"assets": [{"asset_ref": "a", "vendor": "fortinet", "version": "7.2.5"}]}

    first = test_client.post("/api/v1/match", headers={"X-API-Key": raw_key}, json=payload)
    second = test_client.post("/api/v1/match", headers={"X-API-Key": raw_key}, json=payload)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["ratelimit-limit"] == "1"
    assert second.headers["ratelimit-remaining"] == "0"
    assert int(second.headers["ratelimit-reset"]) >= 1
    assert second.headers["retry-after"] == second.headers["ratelimit-reset"]


def test_production_admin_fails_closed_without_trusted_origin_and_access(client, monkeypatch):
    test_client, raw_key, _ = client
    monkeypatch.setenv("OSAK_ENV", "production")
    monkeypatch.setenv("OSAK_KEY_PEPPER", "osak-development-only-pepper")
    monkeypatch.delenv("OSAK_ORIGIN_SHARED_SECRET", raising=False)
    monkeypatch.delenv("OSAK_ADMIN_ACCESS_TOKEN", raising=False)

    response = test_client.get(
        "/api/v1/admin/users",
        headers={
            "X-API-Key": raw_key,
            "CF-Access-Authenticated-User-Email": "admin@example.com",
            "X-Cloudflare-Access-Client-Secret": "spoofed",
        },
    )

    assert response.status_code in {403, 503}


def test_production_admin_requires_admin_key_and_worker_assertion(client, monkeypatch):
    test_client, raw_key, factory = client
    monkeypatch.setenv("OSAK_ENV", "production")
    monkeypatch.setenv("OSAK_KEY_PEPPER", "osak-development-only-pepper")
    monkeypatch.setenv("OSAK_ORIGIN_SHARED_SECRET", "origin-secret")
    monkeypatch.setenv("OSAK_ADMIN_ACCESS_TOKEN", "edge-assertion")
    with factory() as session:
        from osak.accounts.models import User
        from osak.accounts.service import create_key

        user = session.query(User).filter(User.email == "test@example.com").one()
        user.is_admin = True
        raw_key = create_key(session, user, environment="live", allow_multiple=True)
        session.commit()

    response = test_client.get(
        "/api/v1/admin/users",
        headers={
            "X-API-Key": raw_key,
            "X-OSAK-Origin-Secret": "origin-secret",
            "X-OSAK-Admin-Access": "edge-assertion",
        },
    )

    assert response.status_code == 200


def test_signup_is_generic_for_repeated_email(client, monkeypatch):
    test_client, _, _ = client
    payload = {
        "name": "Test User",
        "organization": "OSAK",
        "email": "test@example.com",
        "accept_terms": True,
    }

    first = test_client.post("/api/v1/signup", json=payload)
    second = test_client.post("/api/v1/signup", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert "test@example.com" not in first.text.lower()


def test_signup_sends_one_working_key_email_and_duplicate_does_not_rotate(client, monkeypatch):
    test_client, _, factory = client
    sent: list[str] = []

    def deliver(**kwargs):
        sent.append(kwargs["raw_key"])
        with factory() as session:
            from osak.accounts.service import authenticate_key

            assert authenticate_key(session, kwargs["raw_key"]) is not None
        return True

    monkeypatch.setattr(app_module, "send_api_key_email", deliver)
    payload = {
        "name": "New Signup",
        "organization": "OSAK",
        "email": "single-submit@example.com",
        "accept_terms": True,
    }

    first = test_client.post("/api/v1/signup", json=payload)
    second = test_client.post("/api/v1/signup", json=payload)

    assert first.status_code == second.status_code == 200
    assert "api_key" not in first.json()
    assert len(sent) == 1
    assert test_client.get("/api/v1/me", headers={"X-API-Key": sent[0]}).status_code == 200
    with factory() as session:
        from osak.accounts.models import APIKey, User

        user = session.query(User).filter(User.email == payload["email"]).one()
        assert user.status == "active"
        assert user.email_verified is False
        assert session.query(APIKey).filter(APIKey.user_id == user.id).count() == 1
        assert session.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None)).count() == 1


def test_signup_key_delivery_failure_rolls_back_and_retry_sends_once(client, monkeypatch):
    test_client, _, factory = client
    sent: list[str] = []

    def send_once(**kwargs):
        sent.append(kwargs["raw_key"])
        return len(sent) > 1

    monkeypatch.setattr(app_module, "send_api_key_email", send_once)
    payload = {
        "name": "Retry Signup",
        "organization": "OSAK",
        "email": "retry-submit@example.com",
        "accept_terms": True,
    }

    failed = test_client.post("/api/v1/signup", json=payload)
    succeeded = test_client.post("/api/v1/signup", json=payload)

    assert failed.status_code == 503
    assert succeeded.status_code == 200
    assert len(sent) == 2
    with factory() as session:
        from osak.accounts.models import APIKey, User

        user = session.query(User).filter(User.email == payload["email"]).one()
        assert session.query(APIKey).filter(APIKey.user_id == user.id).count() == 2
        assert session.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None)).count() == 1


def test_signup_does_not_reactivate_disabled_or_admin_accounts(client, monkeypatch):
    test_client, _, factory = client
    sent: list[str] = []
    monkeypatch.setattr(app_module, "send_api_key_email", lambda **kwargs: sent.append(kwargs["raw_key"]) or True)
    with factory() as session:
        from osak.accounts.service import create_user

        create_user(
            session,
            full_name="Disabled User",
            organization="OSAK",
            email="disabled-submit@example.com",
            verified=False,
            status="disabled",
        )
        create_user(
            session,
            full_name="Admin User",
            organization="OSAK",
            email="admin-submit@example.com",
            verified=False,
            status="pending",
            is_admin=True,
        )
        session.commit()

    for email in ("disabled-submit@example.com", "admin-submit@example.com"):
        response = test_client.post(
            "/api/v1/signup",
            json={"name": "Resubmission", "organization": "OSAK", "email": email, "accept_terms": True},
        )
        assert response.status_code == 200
    assert sent == []
    with factory() as session:
        from osak.accounts.models import User

        assert session.query(User).filter(User.email == "disabled-submit@example.com").one().status == "disabled"
        assert session.query(User).filter(User.email == "admin-submit@example.com").one().status == "pending"


def test_signup_verification_endpoint_is_removed_from_public_contract(client):
    test_client, _, _ = client

    assert "/api/v1/signup/verify" not in app_module.app.openapi()["paths"]
    assert test_client.get("/api/v1/signup/verify?token=legacy-token").status_code == 404


def test_signup_email_failure_rolls_back_pending_account(client, monkeypatch):
    test_client, _, factory = client
    monkeypatch.setattr(app_module, "send_api_key_email", lambda **_: False)

    response = test_client.post(
        "/api/v1/signup",
        json={
            "name": "New User",
            "organization": "OSAK",
            "email": "new@example.com",
            "accept_terms": True,
        },
    )

    assert response.status_code == 503
    with factory() as session:
        from osak.accounts.models import APIKey, User

        user = session.query(User).filter(User.email == "new@example.com").one()
        assert user.status == "pending"
        assert session.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None)).count() == 0


def test_signup_db_commit_failure_sends_no_email_and_leaves_no_account(client, monkeypatch):
    test_client, _, factory = client
    from sqlalchemy.exc import SQLAlchemyError

    calls = {"commit": 0}
    sent: list[str] = []

    def flaky_factory():
        session = factory()
        original_commit = session.commit

        def commit():
            calls["commit"] += 1
            if calls["commit"] == 1:
                raise SQLAlchemyError("synthetic commit failure")
            return original_commit()

        session.commit = commit
        return session

    monkeypatch.setattr(app_module, "SessionLocal", flaky_factory)
    monkeypatch.setattr(app_module, "send_api_key_email", lambda **kwargs: sent.append(kwargs["raw_key"]) or True)
    response = test_client.post(
        "/api/v1/signup",
        json={
            "name": "Commit Failure",
            "organization": "OSAK",
            "email": "commit-failure@example.com",
            "accept_terms": True,
        },
    )

    assert response.status_code == 503
    assert sent == []
    with factory() as session:
        from osak.accounts.models import User

        assert session.query(User).filter(User.email == "commit-failure@example.com").count() == 0



def test_manifest_download_matches_published_checksum(client, tmp_path, monkeypatch):
    import hashlib

    from osak.ingest.export import DatasetExporter
    from osak.ingest.persistence import InMemoryRepository

    monkeypatch.setenv("OSAK_DATA_DIR", str(tmp_path))
    api, key, _ = client
    headers = {"X-API-Key": key}
    assert api.get("/api/v1/datasets/latest", headers=headers).status_code == 404
    DatasetExporter(InMemoryRepository(), tmp_path / "exports").export()
    manifest = api.get("/api/v1/datasets/latest", headers=headers).json()
    download = api.get(manifest["download_url"], headers=headers)
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == manifest["sha256"]
    assert api.get(manifest["download_url"]).status_code == 401
    assert api.get("/api/v1/datasets/files/latest.json", headers=headers).status_code == 404
