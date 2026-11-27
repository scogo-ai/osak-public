from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from osak.accounts.models import Base
from osak.accounts.service import create_user, issue_api_key
from osak.core.models import EoLRecord, Product, Vendor
from osak.core.repository import record_change_event, save_canonical_record

app_module = import_module("osak.api.app")


@pytest.fixture()
def release_client(monkeypatch):
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
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with factory() as session:
        user = create_user(
            session,
            full_name="Release User",
            organization="OSAK",
            email="release@example.test",
            verified=True,
        )
        raw_key = issue_api_key(session, user, environment="test")
        for record in (
            Vendor(id="fortinet", name="Fortinet"),
            Product(
                id="fortinet-fortios",
                vendor_id="fortinet",
                family="FortiOS",
                os="fortios",
                scheme="fortios",
            ),
            EoLRecord(
                id="eol-fortios-7.2",
                vendor_id="fortinet",
                product_id="fortinet-fortios",
                version="7.2",
            ),
        ):
            save_canonical_record(session, record)
        for index in range(3):
            record_change_event(
                session,
                record_type="advisory",
                record_id=f"FG-{index}",
                operation="upsert",
                changed_at=now,
            )
        session.commit()
    with TestClient(app_module.app) as client:
        yield client, raw_key, now


def test_eol_resolves_fortios_train_for_concrete_version(release_client):
    client, key, _ = release_client

    supported = client.get(
        "/api/v1/eol?vendor=fortinet&os=fortios&version=7.2.5",
        headers={"X-API-Key": key},
    )
    unsupported = client.get(
        "/api/v1/eol?vendor=fortinet&os=fortios&version=7.4.5",
        headers={"X-API-Key": key},
    )
    vendor_only = client.get(
        "/api/v1/eol?vendor=fortinet&version=7.2.5",
        headers={"X-API-Key": key},
    )

    assert supported.status_code == 200
    assert [item["id"] for item in supported.json()] == ["eol-fortios-7.2"]
    assert unsupported.status_code == 200
    assert unsupported.json() == []
    assert vendor_only.status_code == 200
    assert [item["id"] for item in vendor_only.json()] == ["eol-fortios-7.2"]


def test_changes_sequence_cursor_preserves_equal_timestamp_pages(release_client):
    client, key, since = release_client

    since_query = since.isoformat().replace("+00:00", "Z")
    rows = []
    after_sequence = None
    for _ in range(10):
        cursor = f"&after_sequence={after_sequence}" if after_sequence is not None else ""
        response = client.get(
            f"/api/v1/changes?since={since_query}{cursor}&limit=2",
            headers={"X-API-Key": key},
        )
        assert response.status_code == 200
        batch = response.json()
        if not batch:
            break
        rows.extend(batch)
        after_sequence = batch[-1]["sequence"]

    assert len(rows) == len({row["sequence"] for row in rows})
    assert {"FG-0", "FG-1", "FG-2"}.issubset({row["record_id"] for row in rows})



def test_products_lists_supported_entries_after_the_first_page(release_client):
    client, key, _ = release_client
    with app_module.SessionLocal() as session:
        for index in range(100):
            save_canonical_record(session, Product(
                id=f"fortinet-aaa-{index:03}",
                vendor_id="fortinet",
                family=f"Catalog fixture {index}",
                os="unknown",
                scheme="unknown",
            ))
        session.commit()

    headers = {"X-API-Key": key}
    first = client.get("/api/v1/products?vendor=fortinet", headers=headers)
    second = client.get("/api/v1/products?vendor=fortinet&page=2", headers=headers)
    invalid = client.get("/api/v1/products?vendor=fortinet&page=0", headers=headers)

    assert first.status_code == second.status_code == 200
    assert len(first.json()) == 100
    assert [item["id"] for item in second.json()] == ["fortinet-fortios"]
    assert invalid.status_code == 422
