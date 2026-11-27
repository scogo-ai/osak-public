"""Concrete bindings between MCP and the accounts/API service layers.

The adapters in this module are intentionally narrow.  They call the concrete
account service functions used by REST and the concrete query/matching functions
in ``osak.api.service``; they do not maintain a second key store, quota counter,
or dataset cache.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from osak.core.models import ResolveRequest
from osak.mcp.server import (
    CheckAssetsRequest,
    ExplainVerdictRequest,
    GetAdvisoryRequest,
    GetEOLRequest,
    GetFixOptionsRequest,
    ListNewAdvisoriesRequest,
    MCPAccountGateway,
    MCPPrincipal,
    MCPService,
    MCPUsageMetadata,
    QuotaDecision,
    mount_mcp,
)


def _default_session_factory() -> Any:
    from osak.core.db import SessionLocal

    return SessionLocal()


def _parse_since(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _resolve_vendor_ids(session: Any, values: list[str] | None) -> list[str] | None:
    """Resolve vendor IDs/names/aliases without touching advisory rows."""

    if values is None:
        return None
    from osak.core.db_models import VendorRow

    wanted = {value.casefold().strip() for value in values if value.strip()}
    if not wanted:
        return []
    resolved: list[str] = []
    for row in session.scalars(select(VendorRow).order_by(VendorRow.id)):
        labels = {row.id.casefold(), row.name.casefold()}
        labels.update(alias.casefold() for alias in row.aliases or [])
        if labels & wanted:
            resolved.append(row.id)
    return list(dict.fromkeys(resolved))


class AccountsMCPGateway(MCPAccountGateway):
    """Use the existing account key, quota, and usage persistence functions."""

    def __init__(self, session_factory: Callable[[], Any] | None = None) -> None:
        self._session_factory = session_factory or _default_session_factory

    async def authenticate_api_key(self, token: str) -> MCPPrincipal | None:
        from osak.accounts.service import authenticate_key

        session = self._session_factory()
        try:
            key = authenticate_key(session, token)
            if key is None or key.user is None:
                session.rollback()
                return None
            principal = MCPPrincipal(user_id=str(key.user.id), key_id=str(key.id), max_assets_per_request=key.user.max_assets_per_request)
            session.commit()
            return principal
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    async def check_mcp_quota(
        self,
        principal: MCPPrincipal,
        *,
        request_id: str,
        mcp_tool: str,
        asset_count: int | None,
        user_agent: str | None,
        client_ip: str | None,
    ) -> QuotaDecision:
        from osak.accounts.models import APIKey
        from osak.accounts.service import hash_ip, reserve_usage

        session = self._session_factory()
        try:
            key = session.get(APIKey, principal.key_id)
            if key is None or key.revoked_at is not None or key.user is None:
                session.rollback()
                return QuotaDecision(allowed=False)
            if str(key.user.id) != principal.user_id:
                session.rollback()
                return QuotaDecision(allowed=False)
            quota, reservation = reserve_usage(
                session,
                user=key.user,
                key=key,
                request_id=request_id,
                method="POST",
                route="/mcp",
                query_params={},
                user_agent=user_agent,
                ip_hash=hash_ip(client_ip),
            )
            reservation.asset_count = asset_count  # type: ignore[assignment]
            reservation.mcp_tool_name = mcp_tool  # type: ignore[assignment]
            session.commit()
            return QuotaDecision(allowed=quota.allowed, retry_after=quota.reset_seconds)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    async def record_mcp_usage(self, metadata: MCPUsageMetadata) -> None:
        from osak.accounts.models import UsageLog
        from osak.accounts.service import finalize_usage

        session = self._session_factory()
        try:
            row = (
                session.query(UsageLog)
                .filter(
                    UsageLog.request_id == metadata.request_id,
                    UsageLog.key_id == metadata.principal.key_id,
                )
                .order_by(UsageLog.id.desc())
                .first()
            )
            if row is not None:
                finalize_usage(
                    session,
                    row.id,
                    status=metadata.status,
                    latency_ms=int(metadata.latency_ms),
                    response_size=metadata.response_size or 0,
                    asset_count=metadata.asset_count,
                    mcp_tool_name=metadata.mcp_tool,
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


class APIServiceAdapter(MCPService):
    """Bind typed MCP requests to the existing ``osak.api.service`` functions."""

    def __init__(self, session_factory: Callable[[], Any] | None = None) -> None:
        self._session_factory = session_factory or _default_session_factory

    async def list_new_advisories(self, request: ListNewAdvisoriesRequest) -> Any:
        from osak.core.repository import count_advisories, list_advisories

        session = self._session_factory()
        try:
            since = _parse_since(request.since)
            vendor_ids = _resolve_vendor_ids(session, request.vendors)
            if request.vendors and not vendor_ids:
                return {"items": [], "page": 1, "page_size": 100, "total": 0, "has_more": False}
            page_size = 100
            advisories = list_advisories(
                session,
                vendor_ids=vendor_ids,
                since=since,
                severity=request.min_severity,
                page=1,
                page_size=page_size,
            )
            total = count_advisories(
                session,
                vendor_ids=vendor_ids,
                since=since,
                severity=request.min_severity,
            )
            return {
                "items": advisories,
                "page": 1,
                "page_size": page_size,
                "total": total,
                "has_more": total > page_size,
            }
        finally:
            session.close()

    async def get_advisory(self, request: GetAdvisoryRequest) -> Any:
        from osak.core.repository import get_advisory

        session = self._session_factory()
        try:
            return get_advisory(session, request.id)
        finally:
            session.close()

    async def check_assets(self, request: CheckAssetsRequest) -> Any:
        from osak.api.service import match_request
        from osak.core.models import MatchRequest

        session = self._session_factory()
        try:
            return match_request(
                session,
                MatchRequest(assets=request.assets, filters=request.filters),
            )
        finally:
            session.close()

    async def resolve_inventory(self, request: ResolveRequest) -> Any:
        from osak.api.service import resolve_request

        session = self._session_factory()
        try:
            return resolve_request(session, request)
        finally:
            session.close()

    async def get_fix_options(self, request: GetFixOptionsRequest) -> Any:
        from osak.api.service import get_fix_options

        session = self._session_factory()
        try:
            return get_fix_options(
                session,
                vendor=request.vendor,
                product=request.product,
                version=request.version,
                advisory_id=request.advisory_id,
            )
        finally:
            session.close()

    async def get_eol(self, request: GetEOLRequest) -> Any:
        from osak.api.service import list_eol_records

        session = self._session_factory()
        try:
            return list_eol_records(
                session,
                vendor=request.vendor,
                model=request.model,
                os=request.os,
                version=request.version,
                page=1,
                page_size=100,
            )
        finally:
            session.close()

    async def explain_verdict(self, request: ExplainVerdictRequest) -> Any:
        from osak.api.service import explain_verdict

        session = self._session_factory()
        try:
            return explain_verdict(
                session,
                asset=request.asset,
                advisory_id=request.advisory_id,
            )
        finally:
            session.close()


def mount_accounts_mcp(
    app: Any,
    *,
    session_factory: Callable[[], Any] | None = None,
) -> Any:
    """Mount the concrete account/API adapters into ``osak.api.app.app``."""

    return mount_mcp(
        app,
        APIServiceAdapter(session_factory=session_factory),
        AccountsMCPGateway(session_factory=session_factory),
    )


__all__ = ["APIServiceAdapter", "AccountsMCPGateway", "mount_accounts_mcp"]
