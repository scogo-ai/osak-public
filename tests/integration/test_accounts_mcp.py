from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

if os.getenv("OSAK_RUN_ACCOUNTS_INTEGRATION") != "1":
    pytest.skip(
        "set OSAK_RUN_ACCOUNTS_INTEGRATION=1 for the concrete accounts integration",
        allow_module_level=True,
    )


def _prepend_combined_sources() -> None:
    """Prefer the current integrated source tree for the concrete MCP test."""

    import osak

    local_root = Path(__file__).resolve().parents[2] / "src" / "osak"
    roots = [
        local_root,
        Path("/tmp/osak-build/mcp/src/osak"),
        Path("/tmp/osak-build/match/src/osak"),
    ]
    osak.__path__[:] = [str(root) for root in roots if root.exists()]
    # Keep the integrated tree first while allowing optional worktrees to fill
    # packages that are absent in an older checkout.
    import osak.api
    import osak.core

    osak.__path__[:] = [str(roots[0]), str(roots[2]), str(roots[1])]
    import osak.match

    osak.__path__[:] = [str(roots[0]), str(roots[1]), str(roots[2])]


_prepend_combined_sources()

from osak.accounts.models import UsageLog
from osak.accounts.service import create_key, create_user
from osak.api.app import app
from osak.core import db
from osak.core.models import (
    Advisory,
    AffectedRange,
    Condition,
    EoLRecord,
    Product,
    Provenance,
    Remediation,
    Vendor,
    VersionRange,
)
from osak.core.repository import save_canonical_record
from osak.mcp import mount_accounts_mcp

CANARY = "customer-db-canary-do-not-persist"
UTC_NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def _provenance(source: str = "fixture") -> Provenance:
    return Provenance(
        source=source,
        fetched_at=UTC_NOW,
        url=f"https://example.test/{source}",
        license="facts",
    )


@asynccontextmanager
async def _sdk_client(
    token: str,
) -> AsyncIterator[tuple[ClientSession, httpx.AsyncClient]]:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
            headers={"Authorization": f"Bearer {token}"},
        ) as client,
        streamable_http_client("http://localhost/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _get_session_id,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session, client


@pytest.mark.asyncio
async def test_concrete_accounts_api_service_mcp_end_to_end() -> None:
    db.configure_database("sqlite+pysqlite:///:memory:")
    from osak.accounts import models as _account_models  # noqa: F401

    db.Base.metadata.create_all(db.engine)
    seed_session = db.SessionLocal()
    try:
        user = create_user(
            seed_session,
            full_name="MCP Integration",
            organization="OSAK",
            email="mcp-integration@example.test",
            verified=True,
            requests_per_minute=9,
            requests_per_day=9,
        )
        raw_key = create_key(seed_session, user, environment="test")
        for record in (
            Vendor(id="fortinet", name="Fortinet", provenance=[_provenance("fortinet")]),
            Product(
                id="fortigate",
                vendor_id="fortinet",
                family="FortiGate",
                os="fortios",
                scheme="fortios",
                aliases=["FortiOS"],
                provenance=[_provenance("fortinet")],
            ),
            Advisory(
                id="FG-IR-26-001",
                vendor_id="fortinet",
                title="SSL VPN issue",
                published=datetime(2026, 11, 26, tzinfo=UTC),
                updated=datetime(2026, 11, 27, tzinfo=UTC),
                severity="high",
                cves=["CVE-2026-0001"],
                urls=["https://example.test/FG-IR-26-001"],
                ranges=[
                    AffectedRange(
                        advisory_id="FG-IR-26-001",
                        product_id="fortigate",
                        versions=VersionRange(train="7.2", lower="7.2.0", upper="7.2.8"),
                        status="affected",
                        fixed_versions=["7.2.8"],
                        conditions=[Condition(feature="ssl_vpn")],
                        provenance=[_provenance("fortinet")],
                    )
                ],
                remediation=Remediation(
                    targets=["7.2.8"],
                    workaround="Disable SSL VPN",
                    url="https://example.test/FG-IR-26-001/fix",
                ),
                provenance=[_provenance("fortinet")],
            ),
            EoLRecord(
                id="fortigate-7.2.5",
                vendor_id="fortinet",
                product_id="fortigate",
                model="FG-100F",
                version="7.2",
                end_security=None,
                provenance=[_provenance("fortinet-eol")],
            ),
        ):
            save_canonical_record(seed_session, record)
        seed_session.commit()
    finally:
        seed_session.close()

    mount_accounts_mcp(app, session_factory=db.SessionLocal)

    async with _sdk_client(raw_key) as (session, client):
        names = {tool.name for tool in (await session.list_tools()).tools}
        assert names == {
            "list_new_advisories",
            "get_advisory",
            "check_assets",
            "resolve_inventory",
            "get_fix_options",
            "get_eol",
            "explain_verdict",
        }

        listed = await session.call_tool(
            "list_new_advisories",
            {"since": "2026-11-25T00:00:00Z", "vendors": ["fortinet"]},
        )
        assert listed.isError is False, listed.content
        assert listed.structuredContent["items"][0]["id"] == "FG-IR-26-001"

        advisory = await session.call_tool("get_advisory", {"id": "FG-IR-26-001"})
        assert advisory.structuredContent["title"] == "SSL VPN issue"

        asset = {
            "asset_ref": CANARY,
            "vendor": "fortinet",
            "product": "fortigate",
            "model": "FG-100F",
            "version": "7.2.5",
            "features": ["ssl_vpn"],
        }
        checked = await session.call_tool("check_assets", {"assets": [asset]})
        assert checked.isError is False
        assert checked.structuredContent["results"][0]["findings"][0]["verdict"] == "affected"

        resolved = await session.call_tool(
            "resolve_inventory",
            {"raw_strings": ["Fortinet FortiOS Software, Version 7.2.5"]},
        )
        assert resolved.isError is False
        assert resolved.structuredContent["results"][0]["status"] == "resolved"

        fixed = await session.call_tool(
            "get_fix_options",
            {"vendor": "fortinet", "product": "fortigate", "version": "7.2.5"},
        )
        assert fixed.isError is False
        assert fixed.structuredContent["results"][0]["findings"][0]["fixed_versions"] == ["7.2.8"]

        eol = await session.call_tool("get_eol", {"vendor": "fortinet", "model": "FG-100F"})
        assert eol.isError is False
        assert eol.structuredContent["items"][0]["id"] == "fortigate-7.2.5"

        eol_train = await session.call_tool(
            "get_eol",
            {"vendor": "fortinet", "model": "FG-100F", "os": "fortios", "version": "7.2.5"},
        )
        assert eol_train.isError is False
        assert eol_train.structuredContent["items"][0]["id"] == "fortigate-7.2.5"

        explanation = await session.call_tool(
            "explain_verdict", {"asset": asset, "advisory_id": "FG-IR-26-001"}
        )
        assert explanation.isError is False
        assert explanation.structuredContent["verdict"] == "affected"

        # Switch the same official SDK client to the alternate supported auth header.
        client.headers.pop("Authorization", None)
        client.headers["X-API-Key"] = raw_key
        alternate_auth = await session.call_tool("get_advisory", {"id": "FG-IR-26-001"})
        assert alternate_auth.isError is False

        invalid = await session.call_tool(
            "check_assets", {"assets": [{"asset_ref": CANARY, "vendor": "fortinet"}]}
        )
        assert invalid.isError is True
        assert invalid.content[0].text == "invalid tool input"
        assert CANARY not in json.dumps(invalid.content, default=str)

        exhausted = await session.call_tool("get_advisory", {"id": "FG-IR-26-001"})
        assert exhausted.isError is True
        assert "quota exceeded" in (exhausted.content[0].text or "")

    check_session = db.SessionLocal()
    try:
        rows = check_session.query(UsageLog).order_by(UsageLog.id).all()
        assert len(rows) == 10  # seven tools + train EoL + alternate-auth tool + denied quota call
        assert sum(row.status == 429 for row in rows) == 1
        assert len({row.request_id for row in rows}) == len(rows)
        assert all(row.route == "/mcp" for row in rows)
        assert all(row.query_params == {} for row in rows)
        assert {row.mcp_tool_name for row in rows} == {
            "list_new_advisories",
            "get_advisory",
            "check_assets",
            "resolve_inventory",
            "get_fix_options",
            "get_eol",
            "explain_verdict",
        }
        assert sum(row.mcp_tool_name == "get_advisory" for row in rows) == 3
        assert all(
            row.asset_count == 1
            for row in rows
            if row.mcp_tool_name in {"check_assets", "resolve_inventory", "explain_verdict"}
        )
        assert CANARY not in json.dumps(
            [
                {
                    "request_id": row.request_id,
                    "route": row.route,
                    "status": row.status,
                    "asset_count": row.asset_count,
                    "tool": row.mcp_tool_name,
                    "query": row.query_params,
                }
                for row in rows
            ]
        )
    finally:
        check_session.close()
