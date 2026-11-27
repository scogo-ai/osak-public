"""The ``osak`` administration and local-development CLI."""

from __future__ import annotations

import json
import os
from datetime import datetime

import typer
from sqlalchemy.exc import SQLAlchemyError

from osak.accounts.models import APIKey, UsageLog, User
from osak.accounts.service import create_key, create_user, issue_api_key, revoke_key
from osak.core.db import SessionLocal

app = typer.Typer(help="OSAK administration and local development commands.")
admin_app = typer.Typer(help="Manage users, API keys and usage metadata.")
app.add_typer(admin_app, name="admin")


def _session():
    return SessionLocal()


@app.command("seed")
def seed(
    dev: bool = typer.Option(False, "--dev", help="Create the local development account."),
) -> None:
    """Create a local test account and print its one-time API key."""

    if not dev:
        raise typer.BadParameter("use --dev to seed the local development account")
    if os.getenv("OSAK_ENV", "development").lower() in {"production", "prod"}:
        raise typer.BadParameter("--dev seed is disabled in production")
    session = _session()
    try:
        user = session.query(User).filter(User.email == "dev@localhost").first()
        if user is None:
            user = create_user(
                session,
                full_name="OSAK Development",
                organization="Local development",
                email="dev@localhost",
                verified=True,
            )
        else:
            user.status = "active"
            user.email_verified = True
            for key in session.query(APIKey).filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None)):
                revoke_key(session, key)
        raw_key = issue_api_key(session, user, environment="test")
        session.commit()
    except (ValueError, SQLAlchemyError) as exc:
        session.rollback()
        raise typer.BadParameter(str(exc)) from exc
    finally:
        session.close()
    typer.echo(raw_key)


@admin_app.command("users")
def users(
    action: str = typer.Argument("list", help="list or create"),
    user_id: str | None = typer.Option(None, "--user-id"),
    query: str | None = typer.Option(None, "--query", "-q"),
    full_name: str | None = typer.Option(None, "--name"),
    organization: str | None = typer.Option(None, "--organization"),
    email: str | None = typer.Option(None, "--email"),
    is_admin: bool | None = typer.Option(None, "--admin/--no-admin"),
    status: str | None = typer.Option(None, "--status"),
    plan: str | None = typer.Option(None, "--plan"),
    requests_per_minute: int | None = typer.Option(None, "--rpm", min=1, max=1_000_000),
    requests_per_day: int | None = typer.Option(None, "--rpd", min=1, max=10_000_000),
    max_assets_per_request: int | None = typer.Option(None, "--max-assets", min=1, max=100_000),
) -> None:
    """List users or create one with ``users create``."""

    session = _session()
    try:
        if action == "create":
            if not full_name or not email:
                raise typer.BadParameter("--name and --email are required for users create")
            user = create_user(
                session,
                full_name=full_name,
                organization=organization,
                email=email,
                verified=True,
                is_admin=is_admin or False,
                requests_per_minute=requests_per_minute or 60,
                requests_per_day=requests_per_day or 10_000,
                max_assets_per_request=max_assets_per_request or 500,
            )
            if plan:
                user.plan = plan
            session.commit()
            typer.echo(json.dumps({"id": user.id, "email": user.email}))
            return
        if action == "update":
            if not user_id:
                raise typer.BadParameter("--user-id is required for users update")
            user = session.get(User, user_id)
            if user is None:
                raise typer.BadParameter("user not found")
            if full_name:
                user.full_name = full_name
            if organization is not None:
                user.organization = organization
            if email:
                user.email = email.strip().lower()
            if max_assets_per_request is not None:
                user.max_assets_per_request = max_assets_per_request
            if is_admin is not None:
                user.is_admin = is_admin
            if status:
                user.status = status
            if plan:
                user.plan = plan
            if requests_per_minute is not None:
                user.requests_per_minute = requests_per_minute
            if requests_per_day is not None:
                user.requests_per_day = requests_per_day
            session.commit()
            typer.echo(json.dumps(_user_json(user), default=str))
            return
        if action != "list":
            raise typer.BadParameter("action must be list, create or update")
        statement = session.query(User).order_by(User.created_at)
        if query:
            pattern = f"%{query}%"
            statement = statement.filter(
                (User.email.ilike(pattern))
                | (User.full_name.ilike(pattern))
                | (User.organization.ilike(pattern))
            )
        typer.echo(json.dumps([_user_json(user) for user in statement.all()], default=str))
    except (ValueError, SQLAlchemyError) as exc:
        session.rollback()
        raise typer.BadParameter(str(exc)) from exc
    finally:
        session.close()


@admin_app.command("keys")
def keys(
    action: str = typer.Argument("list", help="list, create or revoke"),
    user_id: str | None = typer.Option(None, "--user-id"),
    key_id: str | None = typer.Option(None, "--key-id"),
    environment: str | None = typer.Option(None, "--environment"),
    label: str | None = typer.Option(None, "--label"),
) -> None:
    """List keys, create one for a user, or revoke one."""

    session = _session()
    try:
        if action == "create":
            if not user_id:
                raise typer.BadParameter("--user-id is required for keys create")
            user = session.get(User, user_id)
            if user is None:
                raise typer.BadParameter("user not found")
            raw_key = create_key(session, user, environment=environment, label=label, allow_multiple=True)
            key = session.query(APIKey).filter(APIKey.user_id == user.id).order_by(APIKey.created_at.desc()).first()
            session.commit()
            typer.echo(json.dumps({"id": key.id, "prefix": key.prefix, "api_key": raw_key}))
            return
        if action == "revoke":
            if not key_id:
                raise typer.BadParameter("--key-id is required for keys revoke")
            key = session.get(APIKey, key_id)
            if key is None:
                raise typer.BadParameter("key not found")
            revoke_key(session, key)
            session.commit()
            typer.echo("revoked")
            return
        if action != "list":
            raise typer.BadParameter("action must be list, create or revoke")
        statement = session.query(APIKey).order_by(APIKey.created_at)
        if user_id:
            statement = statement.filter(APIKey.user_id == user_id)
        typer.echo(json.dumps([_key_json(key) for key in statement.all()], default=str))
    except (ValueError, SQLAlchemyError) as exc:
        session.rollback()
        raise typer.BadParameter(str(exc)) from exc
    finally:
        session.close()


@admin_app.command("usage")
def usage(
    user_id: str | None = typer.Option(None, "--user-id"),
    key_id: str | None = typer.Option(None, "--key-id"),
    endpoint: str | None = typer.Option(None, "--endpoint"),
    from_: datetime | None = typer.Option(None, "--from"),
    to: datetime | None = typer.Option(None, "--to"),
) -> None:
    """Query metadata-only request usage."""

    session = _session()
    try:
        statement = session.query(UsageLog).order_by(UsageLog.timestamp.desc())
        if user_id:
            statement = statement.filter(UsageLog.user_id == user_id)
        if key_id:
            statement = statement.filter(UsageLog.key_id == key_id)
        if endpoint:
            statement = statement.filter(UsageLog.route == endpoint)
        if from_:
            statement = statement.filter(UsageLog.timestamp >= from_)
        if to:
            statement = statement.filter(UsageLog.timestamp <= to)
        typer.echo(json.dumps([_usage_json(row) for row in statement.all()], default=str))
    finally:
        session.close()


def _user_json(user: User) -> dict[str, object]:
    return {
        "id": user.id,
        "full_name": user.full_name,
        "organization": user.organization,
        "email": user.email,
        "status": user.status,
        "plan": user.plan,
        "max_assets_per_request": user.max_assets_per_request,
        "is_admin": user.is_admin,
    }


def _key_json(key: APIKey) -> dict[str, object]:
    return {
        "id": key.id,
        "user_id": key.user_id,
        "prefix": key.prefix,
        "environment": key.environment,
        "created_at": key.created_at,
        "revoked_at": key.revoked_at,
    }


def _usage_json(row: UsageLog) -> dict[str, object]:
    return {
        "request_id": row.request_id,
        "user_id": row.user_id,
        "key_id": row.key_id,
        "timestamp": row.timestamp,
        "method": row.method,
        "route": row.route,
        "query_params": row.query_params,
        "status": row.status,
        "latency_ms": row.latency_ms,
        "response_size": row.response_size,
        "asset_count": row.asset_count,
        "mcp_tool_name": row.mcp_tool_name,
        "user_agent": row.user_agent,
        "ip_hash": row.ip_hash,
    }


@app.command("ingest", add_help_option=False,
             context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def ingest(ctx: typer.Context) -> None:
    """Poll sources and publish snapshots. Use osak ingest --help for options."""
    from osak.ingest.__main__ import main as run_worker

    raise typer.Exit(run_worker(list(ctx.args)))


def main() -> None:
    app()


__all__ = ["admin_app", "app", "main"]
