#!/usr/bin/env python3
"""Run the end-to-end zero-data-retention canary.

The canary sends deliberately unique inventory values through both REST
inventory endpoints and the official MCP SDK. Only after every request has
completed does it read the configured database and live log sinks. A database
or sink that cannot be read is an unavailable check, never a clean result.

Production mode is intentionally explicit: it requires a non-local HTTPS API
URL, a database URL, and at least one live log-sink URL. It performs only
read-like matching/resolution requests and does not mutate production data.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import string
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import LargeBinary, create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError


@dataclass(frozen=True)
class ScanResult:
    found: bool
    locations: tuple[str, ...] = ()
    available: bool = True
    detail: str | None = None


@dataclass(frozen=True)
class UsageAudit:
    rows: tuple[Mapping[str, object], ...] = ()
    available: bool = True
    detail: str | None = None


def new_canary() -> str:
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(24))
    return f"OSAK-ZDR-CANARY-{suffix}"


def canary_payload(canary: str) -> dict[str, object]:
    """Return the REST match payload used by the canary."""

    return {
        "assets": [
            {
                "asset_ref": canary,
                "vendor": "fortinet",
                "product": "fortios",
                "version": "not-a-version",
            }
        ]
    }


def canary_resolve_payload(canary: str) -> dict[str, object]:
    return {"raw_strings": [f"{canary} FortiOS not-a-version"]}


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _is_binary_column(column_type: object) -> bool:
    """Detect bytea/blob columns before constructing a text search."""

    return isinstance(column_type, LargeBinary) or type(column_type).__name__.casefold() in {
        "bytea",
        "blob",
    }


def _column_scan(
    *,
    dialect_name: str,
    table: str,
    column: str,
    column_type: object,
) -> tuple[object, dict[str, object]]:
    table_sql = _quoted_identifier(table)
    column_sql = _quoted_identifier(column)
    if _is_binary_column(column_type):
        if dialect_name == "postgresql":
            return (
                text(
                    f"SELECT 1 FROM {table_sql} "
                    f"WHERE position(decode(:needle_hex, 'hex') in {column_sql}) > 0 LIMIT 1"
                ),
                {"needle_hex": ""},
            )
        return (
            text(f"SELECT 1 FROM {table_sql} WHERE instr({column_sql}, :needle_bytes) > 0 LIMIT 1"),
            {"needle_bytes": b""},
        )
    return (
        text(f"SELECT 1 FROM {table_sql} WHERE CAST({column_sql} AS TEXT) LIKE :needle LIMIT 1"),
        {"needle": ""},
    )


def scan_database(database_url: str, canary: str) -> ScanResult:
    """Search every readable database column, including binary raw blobs.

    Any inspector, connection, or column-query error returns ``available=False``
    instead of silently skipping the column. PostgreSQL bytea is searched as
    bytes via ``decode(..., 'hex')`` so a driver representation cannot hide a
    canary.
    """

    engine = None
    locations: list[str] = []
    try:
        engine = create_engine(database_url)
        database_inspector = inspect(engine)
        with engine.connect() as connection:
            for table in database_inspector.get_table_names():
                for column in database_inspector.get_columns(table):
                    column_name = str(column["name"])
                    statement, parameters = _column_scan(
                        dialect_name=engine.dialect.name,
                        table=table,
                        column=column_name,
                        column_type=column["type"],
                    )
                    if "needle_hex" in parameters:
                        parameters["needle_hex"] = canary.encode("utf-8").hex()
                    elif "needle_bytes" in parameters:
                        parameters["needle_bytes"] = canary.encode("utf-8")
                    else:
                        parameters["needle"] = f"%{canary}%"
                    if connection.execute(statement, parameters).first() is not None:
                        locations.append(f"{table}.{column_name}")
    except (SQLAlchemyError, OSError, ValueError) as exc:
        detail = f"{type(exc).__name__}: database scan unavailable"
        return ScanResult(found=False, available=False, detail=detail)
    finally:
        if engine is not None:
            engine.dispose()
    return ScanResult(found=bool(locations), locations=tuple(locations))


def read_recent_usage(database_url: str, since: datetime) -> UsageAudit:
    """Read only allow-listed request audit metadata written after *since*."""

    engine = None
    try:
        engine = create_engine(database_url)
        inspector = inspect(engine)
        if "usage_logs" not in inspector.get_table_names():
            return UsageAudit(available=False, detail="usage_logs table is unavailable")
        with engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    text(
                        "SELECT route, mcp_tool_name, status, asset_count, request_id, timestamp "
                        "FROM usage_logs WHERE timestamp >= :since ORDER BY timestamp"
                    ),
                    {"since": since},
                ).mappings()
            )
        return UsageAudit(rows=rows)
    except (SQLAlchemyError, OSError, ValueError) as exc:
        return UsageAudit(available=False, detail=f"{type(exc).__name__}: audit unavailable")
    finally:
        if engine is not None:
            engine.dispose()


def scan_log_file(path: Path, canary: str) -> ScanResult:
    """Read a host log file after requests have completed."""

    if not path.exists():
        return ScanResult(found=False, available=False, detail="log file is unavailable")
    try:
        found = canary.encode("utf-8") in path.read_bytes()
    except OSError:
        return ScanResult(found=False, available=False, detail="log file is unreadable")
    return ScanResult(found=found, locations=(str(path),) if found else ())


def scan_log_sink(url: str, canary: str, token: str | None = None) -> ScanResult:
    """Fetch a live sink snapshot after the canary requests."""

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = httpx.get(url, headers=headers, timeout=10)
    except httpx.HTTPError:
        return ScanResult(found=False, available=False, detail="log sink is unreachable")
    if response.status_code < 200 or response.status_code >= 300:
        return ScanResult(
            found=False, available=False, detail="log sink returned a non-success status"
        )
    body = response.content.decode("utf-8", "replace")
    found = canary in body
    return ScanResult(found=found, locations=(url,) if found else ())


def scan_log_text(text_value: str, canary: str, location: str) -> ScanResult:
    """Scan captured host logs without writing their contents to stdout."""

    return ScanResult(found=canary in text_value, locations=(location,) if canary in text_value else ())


def collect_compose_logs(
    *,
    env_file: Path,
    compose_files: Sequence[Path],
    project: str,
    since: datetime,
    canary: str,
    services: Sequence[str],
) -> ScanResult:
    """Capture all origin service logs after the request, in-process only."""

    command = ["docker", "compose", "--env-file", str(env_file)]
    for compose_file in compose_files:
        command.extend(("-f", str(compose_file)))
    command.extend(("-p", project, "logs", "--no-color", "--since", since.isoformat(), *services))
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError):
        return ScanResult(found=False, available=False, detail="origin Compose logs unavailable")
    if completed.returncode != 0:
        return ScanResult(found=False, available=False, detail="origin Compose logs returned an error")
    return scan_log_text(completed.stdout + completed.stderr, canary, "origin-compose-logs")


def _header_values(api_key: str, origin_secret: str | None) -> dict[str, str]:
    headers = {"X-API-Key": api_key}
    if origin_secret:
        headers["X-OSAK-Origin-Secret"] = origin_secret
    return headers


def _assert_json_results(response: httpx.Response, operation: str) -> dict[str, object]:
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(f"{operation} canary request returned HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise RuntimeError(f"{operation} canary response was not JSON") from exc
    if not isinstance(body, dict) or not isinstance(body.get("results"), list):
        raise TypeError(f"{operation} canary response did not contain results")
    return body


def _assert_invalid_rest(response: httpx.Response, operation: str, canary: str) -> None:
    if response.status_code != 422:
        raise RuntimeError(f"invalid {operation} request returned HTTP {response.status_code}")
    if canary in response.content.decode("utf-8", "replace"):
        raise RuntimeError(f"invalid {operation} response echoed the canary")


async def _exercise_mcp(base_url: str, headers: dict[str, str], canary: str) -> None:
    """Exercise real Streamable HTTP MCP tools through the official SDK."""

    async with (
        httpx.AsyncClient(headers=headers, timeout=20) as http_client,
        streamable_http_client(f"{base_url.rstrip('/')}/mcp", http_client=http_client) as (
            read_stream,
            write_stream,
            _get_session_id,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        required = {"check_assets", "resolve_inventory"}
        if not required <= names:
            raise RuntimeError("MCP server did not expose check_assets and resolve_inventory")

        asset = {
            "asset_ref": canary,
            "vendor": "fortinet",
            "product": "fortios",
            "version": "not-a-version",
        }
        check_result = await session.call_tool(
            "check_assets", {"assets": [asset], "filters": {"kev_only": False}}
        )
        if check_result.isError or not check_result.structuredContent:
            raise RuntimeError("MCP check_assets success branch failed")
        if not isinstance(check_result.structuredContent.get("results"), list):
            raise TypeError("MCP check_assets result was not structured")

        resolve_result = await session.call_tool(
            "resolve_inventory", {"raw_strings": [f"{canary} FortiOS not-a-version"]}
        )
        if resolve_result.isError or not resolve_result.structuredContent:
            raise RuntimeError("MCP resolve_inventory success branch failed")
        if not isinstance(resolve_result.structuredContent.get("results"), list):
            raise TypeError("MCP resolve_inventory result was not structured")

        invalid_check = await session.call_tool(
            "check_assets", {"assets": [{"asset_ref": canary, "vendor": "fortinet"}]}
        )
        if not invalid_check.isError:
            raise RuntimeError("MCP check_assets invalid branch unexpectedly succeeded")
        invalid_resolve = await session.call_tool(
            "resolve_inventory", {"raw_strings": [canary, ""]}
        )
        if not invalid_resolve.isError:
            raise RuntimeError("MCP resolve_inventory invalid branch unexpectedly succeeded")
        error_text = json.dumps([invalid_check.content, invalid_resolve.content], default=str)
        if canary in error_text:
            raise RuntimeError("MCP invalid-input error echoed the canary")


def _verify_audit(audit: UsageAudit) -> None:
    if not audit.available:
        raise RuntimeError(audit.detail or "request audit is unavailable")
    routes = {str(row.get("route")) for row in audit.rows}
    tools = {str(row.get("mcp_tool_name")) for row in audit.rows if row.get("mcp_tool_name")}
    successful_routes = {
        str(row.get("route"))
        for row in audit.rows
        if str(row.get("status")) in {"200", "201", "202"}
    }
    successful_tools = {
        str(row.get("mcp_tool_name"))
        for row in audit.rows
        if str(row.get("status")) in {"200", "201", "202"} and row.get("mcp_tool_name")
    }
    required_routes = {"/api/v1/match", "/api/v1/resolve"}
    required_tools = {"check_assets", "resolve_inventory"}
    if not required_routes <= routes:
        raise RuntimeError("request audit is missing REST inventory operations")
    if not required_tools <= tools:
        raise RuntimeError("request audit is missing MCP inventory operations")
    if not required_routes <= successful_routes:
        raise RuntimeError("request audit is missing successful REST inventory operations")
    if not required_tools <= successful_tools:
        raise RuntimeError("request audit is missing successful MCP inventory operations")


def run_canary(
    *,
    base_url: str,
    api_key: str,
    database_url: str,
    log_files: Iterable[Path] = (),
    log_sink_urls: Iterable[str] = (),
    log_sink_token: str | None = None,
    origin_secret: str | None = None,
    compose_env_file: Path | None = None,
    compose_files: Iterable[Path] = (),
    compose_project: str | None = None,
    compose_services: Iterable[str] = (),
    production: bool = False,
    client: httpx.Client | None = None,
) -> None:
    canary = new_canary()
    files = tuple(log_files)
    sinks = tuple(log_sink_urls)
    parsed_url = urlparse(base_url)
    if production:
        if not database_url:
            raise RuntimeError("production ZDR gate requires a database URL")
        if not sinks and compose_env_file is None:
            raise RuntimeError("production ZDR gate requires a live log-sink URL or origin Compose logs")
        if parsed_url.scheme != "https" or parsed_url.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise RuntimeError("production ZDR gate requires a non-local HTTPS API URL")
    if not api_key:
        raise RuntimeError("OSAK_ZDR_API_KEY or --api-key is required")

    headers = _header_values(api_key, origin_secret)
    started_at = datetime.now(UTC)
    close_client = client is None
    http_client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=20)
    try:
        _assert_json_results(
            http_client.post("/api/v1/match", headers=headers, json=canary_payload(canary)),
            "match",
        )
        _assert_json_results(
            http_client.post(
                "/api/v1/resolve", headers=headers, json=canary_resolve_payload(canary)
            ),
            "resolve",
        )
        _assert_invalid_rest(
            http_client.post(
                "/api/v1/match",
                headers=headers,
                json={"assets": [{"asset_ref": canary, "vendor": "fortinet"}]},
            ),
            "match",
            canary,
        )
        _assert_invalid_rest(
            http_client.post(
                "/api/v1/resolve",
                headers=headers,
                json={"raw_strings": [canary, ""]},
            ),
            "resolve",
            canary,
        )
    finally:
        if close_client:
            http_client.close()

    try:
        asyncio.run(_exercise_mcp(base_url, headers, canary))
    except (httpx.HTTPError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(f"MCP canary failed: {type(exc).__name__}") from exc

    results = [scan_database(database_url, canary)] if database_url else []
    # These are intentionally read only now, after all REST and MCP operations.
    if compose_env_file is not None:
        if compose_project is None:
            raise RuntimeError("origin Compose project is required for origin log collection")
        results.append(
            collect_compose_logs(
                env_file=compose_env_file,
                compose_files=tuple(compose_files),
                project=compose_project,
                since=started_at,
                canary=canary,
                services=tuple(compose_services)
                or ("api", "worker", "migrate", "postgres", "backup", "cloudflared"),
            )
        )
    results.extend(scan_log_file(path, canary) for path in files)
    results.extend(scan_log_sink(url, canary, log_sink_token) for url in sinks)
    if any(not result.available for result in results):
        details = "; ".join(
            result.detail or "unavailable sink" for result in results if not result.available
        )
        raise RuntimeError(f"one or more configured ZDR sinks could not be scanned: {details}")
    leaked = [location for result in results if result.found for location in result.locations]
    if leaked:
        raise RuntimeError(f"ZDR canary was found in {len(leaked)} configured sink(s)")
    if database_url:
        _verify_audit(read_recent_usage(database_url, started_at))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("OSAK_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.getenv("OSAK_ZDR_API_KEY", ""))
    parser.add_argument("--db-url", default=os.getenv("OSAK_ZDR_DATABASE_URL", ""))
    parser.add_argument("--log-file", action="append", default=[])
    parser.add_argument("--log-sink-url", action="append", default=[])
    parser.add_argument("--log-sink-token", default=os.getenv("OSAK_ZDR_LOG_SINK_TOKEN"))
    parser.add_argument("--origin-secret", default=os.getenv("OSAK_ORIGIN_SHARED_SECRET"))
    parser.add_argument("--origin-compose-env-file", type=Path)
    parser.add_argument("--origin-compose-file", action="append", type=Path, default=[])
    parser.add_argument("--origin-compose-project")
    parser.add_argument("--origin-compose-service", action="append", default=[])
    parser.add_argument("--production", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        run_canary(
            base_url=args.base_url,
            api_key=args.api_key,
            database_url=args.db_url,
            log_files=(Path(path) for path in args.log_file),
            log_sink_urls=args.log_sink_url,
            log_sink_token=args.log_sink_token,
            origin_secret=args.origin_secret,
            compose_env_file=args.origin_compose_env_file,
            compose_files=args.origin_compose_file,
            compose_project=args.origin_compose_project,
            compose_services=args.origin_compose_service,
            production=args.production,
        )
    except (httpx.HTTPError, RuntimeError, SQLAlchemyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("ZDR canary passed: REST, MCP, database, request audit and live sinks were checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
