from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text

from scripts.qa.zdr_canary import (
    ScanResult,
    UsageAudit,
    _verify_audit,
    canary_payload,
    collect_compose_logs,
    read_recent_usage,
    run_canary,
    scan_database,
    scan_log_file,
)


@pytest.mark.zdr
def test_canary_payload_contains_asset_only_in_request_body() -> None:
    canary = "OSAK-ZDR-CANARY-test"
    payload = canary_payload(canary)

    assert payload["assets"][0]["asset_ref"] == canary
    assert "request_body" not in payload


@pytest.mark.zdr
def test_database_scanner_detects_and_clears_canary(tmp_path: Path) -> None:
    database = tmp_path / "zdr.sqlite"
    engine = create_engine(f"sqlite:///{database}")
    canary = "OSAK-ZDR-CANARY-db"
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE metadata (value TEXT NOT NULL)"))
        connection.execute(text("INSERT INTO metadata(value) VALUES (:value)"), {"value": canary})

    leaked = scan_database(f"sqlite:///{database}", canary)
    assert leaked.found
    assert leaked.locations == ("metadata.value",)

    with engine.begin() as connection:
        connection.execute(text("DELETE FROM metadata"))
    assert not scan_database(f"sqlite:///{database}", canary).found


@pytest.mark.zdr
def test_database_scanner_searches_binary_raw_store_without_casting(tmp_path: Path) -> None:
    database = tmp_path / "zdr-binary.sqlite"
    engine = create_engine(f"sqlite:///{database}")
    canary = "OSAK-ZDR-CANARY-binary"
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE raw_documents (content BLOB NOT NULL)"))
        connection.execute(
            text("INSERT INTO raw_documents(content) VALUES (:content)"),
            {"content": b'{"asset_ref":"' + canary.encode() + b'"}'},
        )

    result = scan_database(f"sqlite:///{database}", canary)
    assert result.found
    assert result.locations == ("raw_documents.content",)


@pytest.mark.zdr
def test_database_scanner_fails_closed_when_database_is_unreadable(tmp_path: Path) -> None:
    result = scan_database(f"sqlite:///{tmp_path / 'missing' / 'zdr.sqlite'}", "OSAK-ZDR-CANARY-db")

    assert not result.found
    assert not result.available


@pytest.mark.zdr
def test_recent_usage_audit_requires_rest_and_mcp_operations(tmp_path: Path) -> None:
    database = tmp_path / "zdr-audit.sqlite"
    engine = create_engine(f"sqlite:///{database}")
    since = datetime.now(UTC) - timedelta(seconds=1)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE usage_logs (route TEXT, mcp_tool_name TEXT, status INTEGER, "
                "asset_count INTEGER, request_id TEXT, timestamp DATETIME)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO usage_logs(route, mcp_tool_name, status, asset_count, request_id, timestamp) "
                "VALUES (:route, :tool, 200, 1, :request_id, :timestamp)"
            ),
            [
                {
                    "route": "/api/v1/match",
                    "tool": None,
                    "request_id": "test-1",
                    "timestamp": since,
                },
                {
                    "route": "/api/v1/resolve",
                    "tool": None,
                    "request_id": "test-2",
                    "timestamp": since,
                },
                {
                    "route": "/mcp",
                    "tool": "check_assets",
                    "request_id": "test-3",
                    "timestamp": since,
                },
                {
                    "route": "/mcp",
                    "tool": "resolve_inventory",
                    "request_id": "test-4",
                    "timestamp": since,
                },
            ],
        )

    audit = read_recent_usage(f"sqlite:///{database}", since - timedelta(seconds=1))
    _verify_audit(audit)


@pytest.mark.zdr
def test_audit_unavailable_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="audit unavailable"):
        _verify_audit(UsageAudit(available=False, detail="audit unavailable"))


@pytest.mark.zdr
def test_production_gate_requires_explicit_live_sink_and_https() -> None:
    with pytest.raises(RuntimeError, match="live log-sink URL"):
        run_canary(
            base_url="http://127.0.0.1:8000",
            api_key="osak_test_unused",
            database_url="sqlite:///unused.sqlite",
            production=True,
        )


@pytest.mark.zdr
def test_log_file_scanner_reports_only_a_match(tmp_path: Path) -> None:
    log_file = tmp_path / "api.log"
    canary = "OSAK-ZDR-CANARY-log"
    log_file.write_text("metadata only\n", encoding="utf-8")
    assert not scan_log_file(log_file, canary).found
    log_file.write_text(f"unexpected {canary}\n", encoding="utf-8")
    assert scan_log_file(log_file, canary).locations == (str(log_file),)


@pytest.mark.zdr
def test_missing_log_file_is_not_reported_as_a_clean_scan(tmp_path: Path) -> None:
    result = scan_log_file(tmp_path / "missing.log", "OSAK-ZDR-CANARY-missing")

    assert not result.found
    assert not result.available


@pytest.mark.zdr
def test_origin_compose_log_scan_is_post_request_and_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    canary = "OSAK-ZDR-CANARY-compose"
    seen: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> CompletedProcess[str]:
        seen.append(command)
        return CompletedProcess(command, 0, stdout=f"api metadata {canary}\n", stderr="")

    monkeypatch.setattr("scripts.qa.zdr_canary.subprocess.run", fake_run)
    result = collect_compose_logs(
        env_file=tmp_path / ".env",
        compose_files=(tmp_path / "prod.yml", tmp_path / "ct203.yml"),
        project="osak-ct203",
        since=datetime.now(UTC),
        canary=canary,
        services=("api", "worker", "postgres"),
    )

    assert result.found
    assert result.locations == ("origin-compose-logs",)
    assert seen[0][-3:] == ["api", "worker", "postgres"]


@pytest.mark.zdr
def test_origin_compose_log_scan_fails_closed_on_command_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "scripts.qa.zdr_canary.subprocess.run",
        lambda command, **_: CompletedProcess(command, 1, stdout="", stderr="unavailable"),
    )

    result = collect_compose_logs(
        env_file=tmp_path / ".env",
        compose_files=(tmp_path / "prod.yml",),
        project="osak-ct203",
        since=datetime.now(UTC),
        canary="OSAK-ZDR-CANARY-compose-error",
        services=("api",),
    )

    assert not result.available


@pytest.mark.zdr
def test_staging_mode_can_use_origin_compose_logs_without_public_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeClient:
        def post(self, path: str, **kwargs: object):
            body = kwargs.get("json", {})
            invalid = (
                isinstance(body, dict)
                and (
                    any("version" not in asset for asset in body.get("assets", []))
                    or "" in body.get("raw_strings", [])
                )
            )
            status = 422 if invalid else 200
            return SimpleNamespace(
                status_code=status,
                content=b"{}",
                json=lambda: {"results": []},
            )

        def close(self) -> None:
            return None

    async def no_mcp(*_: object) -> None:
        return None

    monkeypatch.setattr("scripts.qa.zdr_canary._exercise_mcp", no_mcp)
    monkeypatch.setattr(
        "scripts.qa.zdr_canary.collect_compose_logs",
        lambda **_: ScanResult(found=False),
    )
    monkeypatch.setattr(
        "scripts.qa.zdr_canary.scan_database",
        lambda *_: ScanResult(found=False),
    )
    monkeypatch.setattr(
        "scripts.qa.zdr_canary.read_recent_usage",
        lambda *_: UsageAudit(
            rows=(
                {"route": "/api/v1/match", "status": 200},
                {"route": "/api/v1/resolve", "status": 200},
                {"route": "/mcp", "mcp_tool_name": "check_assets", "status": 200},
                {"route": "/mcp", "mcp_tool_name": "resolve_inventory", "status": 200},
            )
        ),
    )

    run_canary(
        base_url="https://staging.example.invalid",
        api_key="osak_test_staging",
        database_url="sqlite:///staging.sqlite",
        compose_env_file=tmp_path / ".env",
        compose_files=(tmp_path / "prod.yml",),
        compose_project="osak-staging",
        production=True,
        client=FakeClient(),
    )
