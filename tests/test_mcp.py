from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from osak.mcp import QuotaDecision, StaticAPIKeyAuth, create_mcp_app


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.canary = "customer-asset-canary-do-not-log"

    async def list_new_advisories(self, request: Any) -> dict[str, Any]:
        self.calls.append(("list_new_advisories", request.model_dump()))
        return {
            "advisories": [
                {
                    "id": "CVE-2026-0001",
                    "title": "A useful advisory fact",
                    "urls": ["https://vendor.example/advisory"],
                    "raw": {"csaf": "must not be returned"},
                }
            ]
        }

    async def get_advisory(self, request: Any) -> dict[str, Any]:
        self.calls.append(("get_advisory", request.model_dump()))
        return {
            "id": request.id,
            "title": "A useful advisory fact",
            "urls": ["https://vendor.example/advisory"],
        }

    async def check_assets(self, request: Any) -> dict[str, Any]:
        self.calls.append(("check_assets", request.model_dump()))
        return {
            "results": [
                {
                    "asset_ref": request.assets[0].asset_ref,
                    "status": "resolved",
                    "product_id": "fortigate",
                    "findings": [
                        {
                            "advisory_id": "CVE-2026-0001",
                            "verdict": "unknown",
                            "confidence": "low",
                            "reasons": ["fixture result"],
                            "provenance": [
                                {
                                    "source": "fixture",
                                    "fetched_at": "2026-11-27T00:00:00Z",
                                    "url": "https://vendor.example/advisory",
                                    "license": "facts",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    async def resolve_inventory(self, request: Any) -> dict[str, Any]:
        self.calls.append(("resolve_inventory", request.model_dump()))
        return {
            "results": [
                {"status": "unresolved", "vendor": None, "product_id": None, "version": None}
            ]
        }

    async def get_fix_options(self, request: Any) -> dict[str, Any]:
        vendor, product, version = request.vendor, request.product, request.version
        self.calls.append(
            (
                "get_fix_options",
                {
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "advisory_id": request.advisory_id,
                },
            )
        )
        return {
            "vendor": vendor,
            "product": product,
            "version": version,
            "options": [{"target": "7.2.8", "url": "https://vendor.example/fix"}],
        }

    async def get_eol(self, request: Any) -> dict[str, Any]:
        vendor, model, os, version = request.vendor, request.model, request.os, request.version
        self.calls.append(
            ("get_eol", {"vendor": vendor, "model": model, "os": os, "version": version})
        )
        return {
            "vendor": vendor,
            "records": [],
            "links": [{"rel": "source", "href": "https://vendor.example/eol"}],
        }

    async def explain_verdict(self, request: Any) -> dict[str, Any]:
        self.calls.append(("explain_verdict", request.model_dump()))
        return {
            "asset_ref": request.asset.asset_ref,
            "advisory_id": request.advisory_id,
            "verdict": "unknown",
            "reasons": ["insufficient evidence"],
            "links": [{"rel": "advisory", "href": "https://vendor.example/advisory"}],
        }


@asynccontextmanager
async def sdk_client(app: Any, *, token: str | None) -> AsyncIterator[ClientSession]:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=headers
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
async def test_mcp_sdk_exercises_all_tools_and_returns_structured_facts() -> None:
    service = FakeService()
    accounts = StaticAPIKeyAuth({"osak_test_demo": {"user_id": "u-1", "key_id": "k-1"}})

    app = create_mcp_app(
        service,
        accounts,
    )

    async with sdk_client(app, token="osak_test_demo") as session:
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        assert names == {
            "list_new_advisories",
            "get_advisory",
            "check_assets",
            "resolve_inventory",
            "get_fix_options",
            "get_eol",
            "explain_verdict",
        }

        list_result = await session.call_tool(
            "list_new_advisories",
            {"since": "2026-11-26T00:00:00Z", "vendors": ["fortinet"], "min_severity": "high"},
        )
        assert list_result.isError is False
        assert list_result.structuredContent is not None
        assert list_result.structuredContent["advisories"][0]["id"] == "CVE-2026-0001"
        assert "raw" not in list_result.structuredContent["advisories"][0]
        assert (
            list_result.structuredContent["links"][0]["href"] == "https://vendor.example/advisory"
        )

        advisory_result = await session.call_tool("get_advisory", {"id": "CVE-2026-0001"})
        assert advisory_result.structuredContent["id"] == "CVE-2026-0001"

        asset = {
            "asset_ref": service.canary,
            "vendor": "fortinet",
            "product": "fortigate",
            "model": "FG-100F",
            "os": "fortios",
            "version": "7.2.5",
            "features": ["ssl_vpn"],
        }
        check_result = await session.call_tool(
            "check_assets", {"assets": [asset], "filters": {"kev_only": False}}
        )
        assert check_result.isError is False, check_result.content
        assert check_result.structuredContent["results"][0]["status"] == "resolved"

        resolve_result = await session.call_tool(
            "resolve_inventory", {"raw_strings": [service.canary]}
        )
        assert resolve_result.isError is False, resolve_result.content
        assert resolve_result.structuredContent["results"][0]["status"] == "unresolved"

        fix_result = await session.call_tool(
            "get_fix_options",
            {"vendor": "fortinet", "product": "fortigate", "version": "7.2.5"},
        )
        assert fix_result.isError is False, fix_result.content
        assert fix_result.structuredContent["options"][0]["target"] == "7.2.8"

        eol_result = await session.call_tool("get_eol", {"vendor": "fortinet", "os": "fortios"})
        assert eol_result.isError is False, eol_result.content
        assert eol_result.structuredContent["links"][0]["href"] == "https://vendor.example/eol"

        explanation_result = await session.call_tool(
            "explain_verdict", {"asset": asset, "advisory_id": "CVE-2026-0001"}
        )
        assert explanation_result.isError is False, explanation_result.content
        assert explanation_result.structuredContent["verdict"] == "unknown"

    assert len(accounts.usage) == 7
    assert {event.mcp_tool for event in accounts.usage} == {
        "list_new_advisories",
        "get_advisory",
        "check_assets",
        "resolve_inventory",
        "get_fix_options",
        "get_eol",
        "explain_verdict",
    }
    assert all(event.asset_count in (None, 1) for event in accounts.usage)
    assert service.canary not in json.dumps(
        [event.__dict__ for event in accounts.usage], default=str
    )


@pytest.mark.asyncio
async def test_mcp_rejects_missing_or_invalid_api_keys() -> None:
    app = create_mcp_app(
        FakeService(),
        StaticAPIKeyAuth({"osak_test_demo": {"user_id": "u-1", "key_id": "k-1"}}),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as client:
        response = await client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
            headers={
                "X-API-Key": "osak_test_demo",
                "Accept": "application/json, text/event-stream",
            },
        ) as client:
            response = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert response.status_code == 200

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
            headers={"Authorization": "Bearer osak_test_wrong"},
        ) as client:
            response = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert response.status_code == 401


@pytest.mark.asyncio
async def test_mcp_quota_hook_is_shared_and_blocks_the_tool_without_inventory_logging() -> None:
    service = FakeService()

    class DenyCheckAssets(StaticAPIKeyAuth):
        async def check_mcp_quota(
            self,
            principal: Any,
            *,
            request_id: str,
            mcp_tool: str,
            asset_count: int | None,
            user_agent: str | None,
            client_ip: str | None,
        ) -> QuotaDecision:
            return QuotaDecision(allowed=mcp_tool != "check_assets")

    accounts = DenyCheckAssets({"osak_test_demo": {"user_id": "u-1", "key_id": "k-1"}})

    app = create_mcp_app(
        service,
        accounts,
    )

    async with sdk_client(app, token="osak_test_demo") as session:
        result = await session.call_tool(
            "check_assets",
            {
                "assets": [
                    {
                        "asset_ref": service.canary,
                        "vendor": "fortinet",
                        "version": "7.2.5",
                    }
                ]
            },
        )
        assert result.isError is True
        assert "quota" in (result.content[0].text or "").lower()

    assert service.calls == []
    assert service.canary not in json.dumps(
        [event.__dict__ for event in accounts.usage], default=str
    )


@pytest.mark.asyncio
async def test_invalid_json_rpc_tool_input_does_not_log_inventory(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = FakeService()
    accounts = StaticAPIKeyAuth({"osak_test_demo": {"user_id": "u-1", "key_id": "k-1"}})
    app = create_mcp_app(service, accounts)

    async with sdk_client(app, token="osak_test_demo") as session:
        result = await session.call_tool(
            "check_assets",
            {"assets": [{"asset_ref": service.canary, "vendor": "fortinet"}]},
        )
        assert result.isError is True
        assert service.canary not in json.dumps(result.content, default=str)
        assert "invalid tool input" in (result.content[0].text or "")

    assert service.canary not in caplog.text
    assert service.canary not in json.dumps(
        [event.__dict__ for event in accounts.usage], default=str
    )
    assert service.calls == []


def test_tool_input_schema_matches_contract_shape() -> None:
    service = FakeService()
    app = create_mcp_app(
        service,
        StaticAPIKeyAuth({"osak_test_demo": {"user_id": "u-1", "key_id": "k-1"}}),
    )
    server = app.state.mcp_server
    tools = {tool.name: tool for tool in server._tool_manager.list_tools()}

    assert tools["list_new_advisories"].parameters["required"] == ["since"]
    assert tools["get_advisory"].parameters["required"] == ["id"]
    assert tools["check_assets"].parameters["required"] == ["assets"]
    assert tools["check_assets"].parameters["properties"]["assets"]["maxItems"] == 100_000
    assert tools["resolve_inventory"].parameters["required"] == ["raw_strings"]
    assert tools["resolve_inventory"].parameters["properties"]["raw_strings"]["maxItems"] == 500
    assert tools["get_fix_options"].parameters["required"] == ["vendor", "product", "version"]
    assert tools["get_eol"].parameters["required"] == ["vendor"]
    assert tools["explain_verdict"].parameters["required"] == ["asset", "advisory_id"]

@pytest.mark.asyncio
async def test_mcp_uses_the_account_asset_cap_before_matching() -> None:
    service = FakeService()
    accounts = StaticAPIKeyAuth({
        "osak_test_demo": {"user_id": "u1", "key_id": "k1", "max_assets_per_request": 1}
    })
    app = create_mcp_app(service, accounts)
    asset = {"asset_ref": "test", "vendor": "test", "version": "unknown"}
    async with sdk_client(app, token="osak_test_demo") as session:
        result = await session.call_tool("check_assets", {"assets": [asset, asset]})
        assert result.isError
        assert service.calls == []
