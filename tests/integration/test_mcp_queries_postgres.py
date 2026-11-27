from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from osak.accounts.models import APIKey, UsageLog, User
from osak.accounts.service import create_key, create_user
from osak.core.db_models import AdvisoryRow, EnrichmentRow, EoLRecordRow, ProductRow, VendorRow
from osak.core.models import (
    Advisory,
    AffectedRange,
    Enrichment,
    EoLRecord,
    Product,
    Provenance,
    Vendor,
    VersionRange,
)
from osak.core.repository import list_advisories, save_canonical_record
from osak.mcp import AccountsMCPGateway, APIServiceAdapter, mount_mcp

DATABASE_URL = os.getenv("OSAK_MCP_TEST_DATABASE_URL") or os.getenv("OSAK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None,
    reason="set OSAK_MCP_TEST_DATABASE_URL to run MCP PostgreSQL integration tests",
)


def _id(kind: str) -> str:
    return f"mcp-query-{kind}-{uuid4().hex[:12]}"


def _provenance(source: str) -> Provenance:
    return Provenance(
        source=source,
        fetched_at=datetime(2026, 11, 27, 12, 0, tzinfo=UTC),
        url=f"https://example.test/{source}",
        license="test-facts",
    )


@pytest.fixture(scope="module")
def pg_engine():
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.connect() as connection:
        connection.exec_driver_sql("select current_setting('server_version_num')")
    yield engine
    engine.dispose()


@pytest.fixture
def seeded(pg_engine):
    vendor_a = Vendor(id=_id("vendor-a"), name="MCP Vendor A", aliases=["Vendor A"])
    vendor_b = Vendor(id=_id("vendor-b"), name="MCP Vendor B", aliases=["Vendor B"])
    vendor_unrelated = Vendor(id=_id("vendor-unrelated"), name="MCP Unrelated")
    product_a = Product(
        id=_id("product-a"),
        vendor_id=vendor_a.id,
        family="FortiGate A",
        os="fortios",
        scheme="fortios",
    )
    product_b = Product(
        id=_id("product-b"),
        vendor_id=vendor_b.id,
        family="FortiGate B",
        os="fortios",
        scheme="fortios",
    )
    product_unrelated = Product(
        id=_id("product-unrelated"),
        vendor_id=vendor_unrelated.id,
        family="Unrelated",
        os="fortios",
        scheme="fortios",
    )

    def advisory(vendor: Vendor, product: Product, label: str, cve: str, severity: str) -> Advisory:
        advisory_id = _id(f"advisory-{label}")
        return Advisory(
            id=advisory_id,
            vendor_id=vendor.id,
            title=f"{label} advisory",
            published=datetime(2026, 11, 26, tzinfo=UTC),
            updated=datetime(2026, 11, 27, tzinfo=UTC),
            severity=severity,
            cves=[cve],
            urls=[f"https://example.test/{label}"],
            ranges=[
                AffectedRange(
                    advisory_id=advisory_id,
                    product_id=product.id,
                    versions=VersionRange(train="7.2", lower="7.2.0", upper="7.2.8"),
                    status="affected",
                    fixed_versions=["7.2.8"],
                    provenance=[_provenance(label)],
                )
            ],
            provenance=[_provenance(label)],
        )

    advisory_a = advisory(vendor_a, product_a, "vendor-a", _id("cve-a"), "high")
    advisory_b = advisory(vendor_b, product_b, "vendor-b", _id("cve-b"), "high")
    advisory_low = advisory(vendor_a, product_a, "vendor-a-low", _id("cve-low"), "low")
    advisory_unrelated = advisory(
        vendor_unrelated, product_unrelated, "unrelated", _id("cve-unrelated"), "critical"
    )
    eol_a = EoLRecord(
        id=_id("eol-a"),
        vendor_id=vendor_a.id,
        product_id=product_a.id,
        model="MCP-100",
        version="7.2.5",
        end_security=None,
        provenance=[_provenance("eol-a")],
    )
    all_records = [
        vendor_a,
        vendor_b,
        vendor_unrelated,
        product_a,
        product_b,
        product_unrelated,
        advisory_a,
        advisory_b,
        advisory_low,
        advisory_unrelated,
        Enrichment(cve_id=advisory_a.cves[0], kev=True, provenance=[_provenance("kev")]),
        Enrichment(cve_id=advisory_b.cves[0], kev=True, provenance=[_provenance("kev")]),
        Enrichment(cve_id=advisory_low.cves[0], kev=False, provenance=[_provenance("epss")]),
        Enrichment(cve_id=advisory_unrelated.cves[0], kev=False, provenance=[_provenance("epss")]),
        eol_a,
    ]
    user_ids: list[str] = []
    key_ids: list[str] = []
    session = Session(pg_engine, expire_on_commit=False)
    try:
        for record in all_records:
            save_canonical_record(session, record)
        user = create_user(
            session,
            full_name="MCP PostgreSQL Query Test",
            organization="OSAK Tests",
            email=f"{_id('user')}@example.test",
            verified=True,
            requests_per_minute=100,
            requests_per_day=100,
        )
        raw_key = create_key(session, user, environment="test")
        user_ids.append(user.id)
        session.flush()
        key = session.query(APIKey).filter(APIKey.user_id == user.id).one()
        key_ids.append(key.id)
        session.commit()
    finally:
        session.close()

    try:
        yield {
            "raw_key": raw_key,
            "user_id": user_ids[0],
            "key_id": key_ids[0],
            "vendors": (vendor_a, vendor_b, vendor_unrelated),
            "products": (product_a, product_b, product_unrelated),
            "advisories": (advisory_a, advisory_b, advisory_low, advisory_unrelated),
            "eol": eol_a,
        }
    finally:
        cleanup = Session(pg_engine, expire_on_commit=False)
        try:
            cleanup.execute(delete(UsageLog).where(UsageLog.user_id.in_(user_ids)))
            cleanup.execute(delete(APIKey).where(APIKey.user_id.in_(user_ids)))
            cleanup.execute(delete(User).where(User.id.in_(user_ids)))
            advisory_ids = [
                record.id for record in (advisory_a, advisory_b, advisory_low, advisory_unrelated)
            ]
            product_ids = [record.id for record in (product_a, product_b, product_unrelated)]
            vendor_ids = [record.id for record in (vendor_a, vendor_b, vendor_unrelated)]
            cleanup.execute(delete(AdvisoryRow).where(AdvisoryRow.id.in_(advisory_ids)))
            cleanup.execute(
                delete(EnrichmentRow).where(
                    EnrichmentRow.cve_id.in_(
                        [
                            item.cves[0]
                            for item in (advisory_a, advisory_b, advisory_low, advisory_unrelated)
                        ]
                    )
                )
            )
            cleanup.execute(delete(EoLRecordRow).where(EoLRecordRow.id == eol_a.id))
            cleanup.execute(delete(ProductRow).where(ProductRow.id.in_(product_ids)))
            cleanup.execute(delete(VendorRow).where(VendorRow.id.in_(vendor_ids)))
            cleanup.commit()
        finally:
            cleanup.close()


@asynccontextmanager
async def _sdk_client(app: FastAPI, token: str) -> AsyncIterator[ClientSession]:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
            headers={"Authorization": f"Bearer {token}"},
        ) as http_client,
        streamable_http_client("http://localhost/mcp", http_client=http_client) as (
            read_stream,
            write_stream,
            _get_session_id,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


@pytest.mark.asyncio
async def test_mcp_queries_are_indexed_scoped_and_quota_bound(pg_engine, seeded) -> None:
    vendor_a, vendor_b, _vendor_unrelated = seeded["vendors"]
    advisory_a, advisory_b, advisory_low, advisory_unrelated = seeded["advisories"]
    session = Session(pg_engine, expire_on_commit=False)
    try:
        kev_ids = {
            item.id
            for item in list_advisories(session, vendor_ids=[vendor_a.id, vendor_b.id], kev=True)
        }
        non_kev_ids = {
            item.id
            for item in list_advisories(session, vendor_ids=[vendor_a.id, vendor_b.id], kev=False)
        }
        assert kev_ids == {advisory_a.id, advisory_b.id}
        assert non_kev_ids == {advisory_low.id}
    finally:
        session.close()

    app = FastAPI()
    mount_mcp(
        app,
        APIServiceAdapter(session_factory=lambda: Session(pg_engine, expire_on_commit=False)),
        AccountsMCPGateway(session_factory=lambda: Session(pg_engine, expire_on_commit=False)),
    )
    async with _sdk_client(app, seeded["raw_key"]) as client:
        listed = await client.call_tool(
            "list_new_advisories",
            {
                "since": "2026-11-25T00:00:00Z",
                "vendors": [vendor_a.name, vendor_b.id],
                "min_severity": "high",
            },
        )
        assert listed.isError is False
        listed_ids = {item["id"] for item in listed.structuredContent["items"]}
        assert listed_ids == {advisory_a.id, advisory_b.id}
        assert listed.structuredContent["total"] == 2
        assert listed.structuredContent["has_more"] is False

        advisory = await client.call_tool("get_advisory", {"id": advisory_b.cves[0]})
        assert advisory.isError is False
        assert advisory.structuredContent["id"] == advisory_b.id
        assert advisory_unrelated.id not in json.dumps(advisory.structuredContent)

        eol = await client.call_tool(
            "get_eol",
            {"vendor": vendor_a.name, "model": "MCP-100", "version": "7.2.5"},
        )
        assert eol.isError is False
        assert eol.structuredContent["items"][0]["id"] == seeded["eol"].id

        fixed = await client.call_tool(
            "get_fix_options",
            {"vendor": vendor_a.id, "product": seeded["products"][0].id, "version": "7.2.5"},
        )
        assert fixed.isError is False
        assert fixed.structuredContent["results"][0]["findings"]
        assert advisory_unrelated.id not in json.dumps(fixed.structuredContent)

        explained = await client.call_tool(
            "explain_verdict",
            {
                "asset": {
                    "asset_ref": "mcp-query-asset",
                    "vendor": vendor_a.id,
                    "product": seeded["products"][0].id,
                    "version": "7.2.5",
                },
                "advisory_id": advisory_a.id,
            },
        )
        assert explained.isError is False
        assert advisory_unrelated.id not in json.dumps(explained.structuredContent)
        assert seeded["raw_key"] not in json.dumps(
            [listed.structuredContent, advisory.structuredContent, eol.structuredContent]
        )


@pytest.mark.asyncio
async def test_mcp_postgres_quota_rejects_second_tool_call(seeded, pg_engine) -> None:
    session = Session(pg_engine, expire_on_commit=False)
    try:
        user = create_user(
            session,
            full_name="MCP Quota Test",
            organization="OSAK Tests",
            email=f"{_id('quota-user')}@example.test",
            verified=True,
            requests_per_minute=1,
            requests_per_day=1,
        )
        raw_key = create_key(session, user, environment="test")
        session.commit()
        user_id = user.id
    finally:
        session.close()

    try:
        app = FastAPI()
        mount_mcp(
            app,
            APIServiceAdapter(session_factory=lambda: Session(pg_engine, expire_on_commit=False)),
            AccountsMCPGateway(session_factory=lambda: Session(pg_engine, expire_on_commit=False)),
        )
        async with _sdk_client(app, raw_key) as client:
            invalid = await client.call_tool(
                "check_assets",
                {"assets": [{"asset_ref": "mcp-query-invalid", "vendor": "fortinet"}]},
            )
            first = await client.call_tool("get_advisory", {"id": seeded["advisories"][0].id})
            second = await client.call_tool("get_advisory", {"id": seeded["advisories"][0].id})
            assert invalid.isError is True
            assert invalid.content[0].text == "invalid tool input"
            assert "mcp-query-invalid" not in str(invalid.content)
            assert first.isError is False
            assert second.isError is True
            assert "quota exceeded" in (second.content[0].text or "")
        usage_session = Session(pg_engine, expire_on_commit=False)
        try:
            usage_rows = usage_session.query(UsageLog).filter(UsageLog.user_id == user_id).all()
        finally:
            usage_session.close()
        assert sorted(row.status for row in usage_rows) == [200, 429]
    finally:
        cleanup = Session(pg_engine, expire_on_commit=False)
        try:
            cleanup.execute(delete(UsageLog).where(UsageLog.user_id == user_id))
            cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            cleanup.execute(delete(User).where(User.id == user_id))
            cleanup.commit()
        finally:
            cleanup.close()
