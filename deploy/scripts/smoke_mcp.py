"""Exercise the public Streamable HTTP transport with the release smoke key."""

import asyncio
import os

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main() -> None:
    base = os.environ.get(
        "OSAK_SMOKE_BASE_URL", os.environ.get("OSAK_BASE_URL", "https://osak.lab.scogo.ai")
    ).rstrip("/")
    asset = {
        "asset_ref": "release-smoke",
        "vendor": "fortinet",
        "os": "FortiOS",
        "version": "7.2.4",
    }
    advisory_id = "CVE-2023-33301"
    fix_id = "CVE-2023-24510"
    calls = {
        "list_new_advisories": {"since": "2023-10-01T00:00:00Z", "vendors": ["fortinet"]},
        "get_advisory": {"id": advisory_id},
        "check_assets": {"assets": [asset]},
        "resolve_inventory": {"raw_strings": ["Fortinet FortiOS 7.2.4"]},
        "get_fix_options": {
            "vendor": "arista",
            "product": "arista-eos",
            "version": "4.28.0F",
            "advisory_id": fix_id,
        },
        "get_eol": {"vendor": "fortinet", "os": "FortiOS", "version": "7.2"},
        "explain_verdict": {"asset": asset, "advisory_id": advisory_id},
    }
    async with (
        httpx.AsyncClient(
            headers={
                "Authorization": "Bearer " + os.environ["OSAK_SMOKE_TEST_KEY"],
                **(
                    {"X-OSAK-Origin-Secret": os.environ["OSAK_ORIGIN_SHARED_SECRET"]}
                    if os.environ.get("OSAK_ORIGIN_SHARED_SECRET")
                    else {}
                ),
            }
        ) as client,
        streamable_http_client(base + "/mcp", http_client=client) as (incoming, outgoing, _),
        ClientSession(incoming, outgoing) as session,
    ):
        await session.initialize()
        tools = {tool.name for tool in (await session.list_tools()).tools}
        if not calls.keys() <= tools:
            raise RuntimeError("Required tools missing from public MCP transport")
        for name, args in calls.items():
            result = await session.call_tool(name, args)
            if result.isError or not result.structuredContent:
                raise RuntimeError(f"MCP smoke failed for {name}")
            body = result.structuredContent
            items = body.get("items") or []
            results = body.get("results") or []
            if name == "get_advisory":
                correct = (
                    body.get("id") == advisory_id or advisory_id in body.get("cves", [])
                ) and body.get("provenance")
            elif name == "list_new_advisories":
                correct = items and all(item.get("vendor_id") == "fortinet" for item in items)
            elif name == "check_assets":
                correct = (
                    results
                    and results[0].get("asset_ref") == asset["asset_ref"]
                    and any(
                        f.get("advisory_id") and f.get("provenance")
                        for f in results[0].get("findings", [])
                    )
                )
            elif name == "resolve_inventory":
                correct = (
                    results
                    and results[0].get("product_id") == "fortinet-fortios"
                    and results[0].get("version") == "7.2.4"
                )
            elif name == "get_fix_options":
                correct = any(
                    f.get("advisory_id") == fix_id and "4.28.7M" in f.get("fixed_versions", [])
                    for f in items
                )
            elif name == "get_eol":
                correct = any(
                    row.get("product_id") == "fortinet-fortios" and row.get("version") == "7.2"
                    for row in items
                )
            else:
                correct = (
                    body.get("advisory_id") == advisory_id
                    and body.get("reasons")
                    and body.get("provenance")
                )
            if not correct:
                raise RuntimeError(f"MCP smoke returned incomplete publisher facts for {name}")
            print(name, "OK")


if __name__ == "__main__":
    asyncio.run(main())
