"""OSAK's authenticated, stateless Streamable HTTP MCP server.

This module is deliberately an adapter, not a second API implementation.  The
REST application supplies one typed ``MCPAccountGateway`` for account/auth,
quota, and usage handling and one typed ``MCPService`` for advisory operations.
The MCP process does not own keys, persistence, or matching logic.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Protocol, cast

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.tools.base import Tool
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import UrlElicitationRequiredError
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from osak.core.models import Asset, MatchFilters, ResolveRequest

logger = logging.getLogger(__name__)

MCP_PATH = "/mcp"
MAX_ASSETS = 100_000
DEFAULT_ALLOWED_HOSTS = [
    "localhost",
    "localhost:*",
    "127.0.0.1",
    "127.0.0.1:*",
    "[::1]",
    "[::1]:*",
    "osak.lab.scogo.ai",
]


class MCPModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListNewAdvisoriesRequest(MCPModel):
    since: str
    vendors: list[str] | None = None
    min_severity: str | None = None


class GetAdvisoryRequest(MCPModel):
    id: str


class CheckAssetsRequest(MCPModel):
    assets: list[Asset] = Field(min_length=1, max_length=MAX_ASSETS)
    filters: MatchFilters = Field(default_factory=MatchFilters)


class GetFixOptionsRequest(MCPModel):
    vendor: str
    product: str
    version: str
    advisory_id: str | None = None


class GetEOLRequest(MCPModel):
    vendor: str
    model: str | None = None
    os: str | None = None
    version: str | None = None


class ExplainVerdictRequest(MCPModel):
    asset: Asset
    advisory_id: str


_ASSETS_FIELD = Field(min_length=1, max_length=MAX_ASSETS)
_FILTERS_FIELD = Field(default_factory=MatchFilters)
_RAW_STRINGS_FIELD = Field(min_length=1, max_length=500)
RawInventoryString = Annotated[str, Field(min_length=1, max_length=2048)]


class MCPService(Protocol):
    """Typed service-layer contract shared by REST and MCP."""

    async def list_new_advisories(self, request: ListNewAdvisoriesRequest) -> Any: ...

    async def get_advisory(self, request: GetAdvisoryRequest) -> Any: ...

    async def check_assets(self, request: CheckAssetsRequest) -> Any: ...

    async def resolve_inventory(self, request: ResolveRequest) -> Any: ...

    async def get_fix_options(self, request: GetFixOptionsRequest) -> Any: ...

    async def get_eol(self, request: GetEOLRequest) -> Any: ...

    async def explain_verdict(self, request: ExplainVerdictRequest) -> Any: ...


@dataclass(frozen=True)
class MCPPrincipal:
    """Account identity returned by the shared accounts gateway."""

    user_id: str
    key_id: str
    max_assets_per_request: int = 500


@dataclass(frozen=True)
class QuotaDecision:
    """Typed result from the shared account quota check."""

    allowed: bool
    retry_after: int | None = None


@dataclass(frozen=True)
class MCPUsageMetadata:
    """Metadata passed to accounts; no tool arguments or request body are included."""

    request_id: str
    principal: MCPPrincipal
    timestamp: datetime
    method: str
    route: str
    status: int
    latency_ms: float
    response_size: int | None
    asset_count: int | None
    mcp_tool: str
    user_agent: str | None
    client_ip: str | None


class MCPAccountGateway(Protocol):
    """Single explicit seam for accounts/auth, quota, and metadata-only usage.

    ``record_mcp_usage`` is responsible for applying the account subsystem's
    retention and IP hashing/truncation policy.  The MCP adapter never persists
    or logs this metadata itself.
    """

    async def authenticate_api_key(self, token: str) -> MCPPrincipal | None: ...

    async def check_mcp_quota(
        self,
        principal: MCPPrincipal,
        *,
        request_id: str,
        mcp_tool: str,
        asset_count: int | None,
        user_agent: str | None,
        client_ip: str | None,
    ) -> QuotaDecision: ...

    async def record_mcp_usage(self, metadata: MCPUsageMetadata) -> None: ...


@dataclass(frozen=True)
class _MCPRequest:
    request_id: str
    principal: MCPPrincipal | None
    method: str
    route: str
    user_agent: str | None
    client_ip: str | None


@dataclass
class _MCPState:
    request: _MCPRequest
    status: int = 200
    tool: str | None = None
    asset_count: int | None = None
    started: float = 0.0


_current_request: ContextVar[_MCPState | None] = ContextVar("osak_mcp_request", default=None)


class StaticAPIKeyAuth:
    """In-process account gateway for local tests and self-hosted examples only."""

    def __init__(self, keys: Mapping[str, MCPPrincipal | Mapping[str, Any]]) -> None:
        self._keys = dict(keys)
        self.usage: list[MCPUsageMetadata] = []

    async def authenticate_api_key(self, token: str) -> MCPPrincipal | None:
        account = self._keys.get(token)
        if account is None:
            return None
        if isinstance(account, MCPPrincipal):
            return account
        return MCPPrincipal(
            user_id=str(account.get("user_id", account.get("id", "unknown"))),
            key_id=str(account.get("key_id", "unknown")),
            max_assets_per_request=int(account.get("max_assets_per_request", 500)),
        )

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
        return QuotaDecision(allowed=True)

    async def record_mcp_usage(self, metadata: MCPUsageMetadata) -> None:
        self.usage.append(metadata)


class _SafeTool(Tool):
    """Official SDK tool that does not echo invalid arguments in errors."""

    async def run(
        self,
        arguments: dict[str, Any],
        context: Any = None,
        convert_result: bool = False,
    ) -> Any:
        try:
            result = await self.fn_metadata.call_fn_with_arg_validation(
                self.fn,
                self.is_async,
                arguments,
                {self.context_kwarg: context} if self.context_kwarg is not None else None,
            )
            if convert_result:
                result = self.fn_metadata.convert_result(result)
            return result
        except UrlElicitationRequiredError:
            raise
        except ValidationError:
            raise ToolError("invalid tool input") from None
        except ToolError:
            raise
        except Exception:  # noqa: BLE001
            raise ToolError(f"Error executing tool {self.name}: service request failed") from None


def _harden_tool_validation(server: FastMCP) -> None:
    """Replace registered SDK tools with the safe-error subclass in place."""

    manager = server._tool_manager
    manager._tools = {
        name: _SafeTool.model_construct(**tool.__dict__)
        for name, tool in manager._tools.items()
    }


def _header_value(scope: Scope, name: str) -> str | None:
    value = Headers(scope=scope).get(name)
    return value.strip() if value else None


def _token_from_scope(scope: Scope) -> str | None:
    authorization = _header_value(scope, "authorization")
    if authorization:
        scheme, separator, credentials = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and credentials.strip():
            return credentials.strip()
        return None
    return _header_value(scope, "x-api-key")


def _client_ip(scope: Scope) -> str | None:
    client = scope.get("client")
    return str(client[0]) if client else None


def _as_json(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _as_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_as_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return str(value)


_RAW_KEYS = frozenset({"raw", "raw_document", "raw_documents", "csaf", "csaf_document"})


def _compact(value: Any) -> Any:
    """Keep structured facts while dropping raw advisory documents."""

    value = _as_json(value)
    if isinstance(value, Mapping):
        return {
            key: _compact(item)
            for key, item in value.items()
            if key.casefold() not in _RAW_KEYS and not isinstance(item, bytes)
        }
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def _collect_links(value: Any) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(rel: str, href: Any) -> None:
        if not isinstance(href, str) or not href.startswith(("https://", "http://")):
            return
        pair = (rel, href)
        if pair not in seen:
            seen.add(pair)
            links.append({"rel": rel, "href": href})

    def visit(item: Any, relation: str = "source") -> None:
        if isinstance(item, Mapping):
            existing = item.get("links")
            if isinstance(existing, list):
                for link in existing:
                    if isinstance(link, Mapping):
                        add(str(link.get("rel", relation)), link.get("href", link.get("url")))
            for key, child in item.items():
                normalized = str(key).casefold()
                if normalized in {"url", "source_url"}:
                    add(relation, child)
                elif normalized == "advisory_url":
                    add("advisory", child)
                elif normalized == "urls" and isinstance(child, list):
                    for url in child:
                        add("advisory", url)
                elif normalized == "provenance":
                    visit(child, "source")
                elif normalized not in _RAW_KEYS:
                    visit(child, relation)
        elif isinstance(item, list):
            for child in item:
                visit(child, relation)

    visit(value)
    return links


def _response(value: Any) -> dict[str, Any]:
    compact = _compact(value)
    links = _collect_links(compact)
    if isinstance(compact, dict):
        result = dict(compact)
        existing_links = result.get("links")
        if isinstance(existing_links, list):
            result["links"] = list(existing_links)
            existing_pairs = {
                (str(item.get("rel", "source")), str(item.get("href", "")))
                for item in existing_links
                if isinstance(item, Mapping)
            }
            result["links"].extend(
                link for link in links if (link["rel"], link["href"]) not in existing_pairs
            )
        else:
            result["links"] = links
        return result
    if isinstance(compact, list):
        return {"items": compact, "links": links}
    return {"value": compact, "links": links}


async def _record_usage(accounts: MCPAccountGateway, state: _MCPState, status: int) -> None:
    principal = state.request.principal
    if principal is None or state.tool is None:
        return
    metadata = MCPUsageMetadata(
        request_id=state.request.request_id,
        principal=principal,
        timestamp=datetime.now(UTC),
        method=state.request.method,
        route=state.request.route,
        status=status,
        latency_ms=round((time.perf_counter() - state.started) * 1000, 3),
        response_size=None,
        asset_count=state.asset_count,
        mcp_tool=state.tool,
        user_agent=state.request.user_agent,
        client_ip=state.request.client_ip,
    )
    try:
        await accounts.record_mcp_usage(metadata)
    except Exception:  # pragma: no cover - logging must not break a tool call  # noqa: BLE001
        logger.warning("MCP usage logger failed")


async def _execute(
    accounts: MCPAccountGateway,
    state: _MCPState,
    tool: str,
    asset_count: int | None,
    operation: Callable[[], Awaitable[Any]],
) -> dict[str, Any]:
    state.tool = tool
    state.asset_count = asset_count
    principal = state.request.principal
    if principal is None:
        raise ToolError("authentication required")
    try:
        decision = await accounts.check_mcp_quota(
            principal,
            request_id=state.request.request_id,
            mcp_tool=tool,
            asset_count=asset_count,
            user_agent=state.request.user_agent,
            client_ip=state.request.client_ip,
        )
    except Exception:  # noqa: BLE001
        state.status = 503
        await _record_usage(accounts, state, 503)
        raise ToolError("quota check unavailable") from None
    if not decision.allowed:
        state.status = 429
        await _record_usage(accounts, state, 429)
        raise ToolError("quota exceeded")
    if tool == "check_assets" and asset_count is not None and asset_count > principal.max_assets_per_request:
        state.status = 422
        await _record_usage(accounts, state, 422)
        raise ToolError("account asset limit exceeded")
    try:
        result = await operation()
    except Exception:  # noqa: BLE001
        state.status = 500
        await _record_usage(accounts, state, 500)
        raise ToolError("service request failed") from None
    if result is None and tool in {"get_advisory", "explain_verdict"}:
        state.status = 404
        await _record_usage(accounts, state, 404)
        raise ToolError("No advisory finding for this request")
    await _record_usage(accounts, state, 200)
    return _response(result)


class _MCPAuthApp:
    def __init__(self, app: ASGIApp, accounts: MCPAccountGateway) -> None:
        self.app = app
        self.accounts = accounts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = _MCPRequest(
            request_id=str(uuid.uuid4()),
            principal=None,
            method=str(scope.get("method", "")),
            route=MCP_PATH,
            user_agent=_header_value(scope, "user-agent"),
            client_ip=_client_ip(scope),
        )
        state = _MCPState(request=request, started=time.perf_counter())
        token = _current_request.set(state)
        try:
            api_key = _token_from_scope(scope)
            principal = None
            if api_key:
                try:
                    principal = await self.accounts.authenticate_api_key(api_key)
                except Exception:  # noqa: BLE001
                    principal = None
            if principal is None:
                await _send_unauthorized(send)
                return
            state.request = _MCPRequest(
                request_id=request.request_id,
                principal=principal,
                method=request.method,
                route=request.route,
                user_agent=request.user_agent,
                client_ip=request.client_ip,
            )
            await self.app(scope, receive, send)
        finally:
            _current_request.reset(token)


async def _send_unauthorized(send: Send) -> None:
    body = b'{"detail":"authentication required"}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _register_tools(server: FastMCP, service: MCPService, accounts: MCPAccountGateway) -> None:
    @server.tool(
        name="list_new_advisories",
        description="List compact advisory facts published or updated since a timestamp, with source links.",
        structured_output=True,
    )
    async def list_new_advisories(
        since: str,
        vendors: list[str] | None = None,
        min_severity: str | None = None,
    ) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = ListNewAdvisoriesRequest(
            since=since,
            vendors=vendors,
            min_severity=min_severity,
        )
        return await _execute(
            accounts,
            state,
            "list_new_advisories",
            None,
            lambda: service.list_new_advisories(request),
        )

    @server.tool(
        name="get_advisory",
        description="Get compact structured facts and source links for one advisory or CVE.",
        structured_output=True,
    )
    async def get_advisory(id: str) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        return await _execute(
            accounts,
            state,
            "get_advisory",
            None,
            lambda: service.get_advisory(GetAdvisoryRequest(id=id)),
        )

    @server.tool(
        name="check_assets",
        description="Defensively check supplied inventory against advisory facts; inventory is never retained.",
        structured_output=True,
    )
    async def check_assets(
        assets: list[Asset] = _ASSETS_FIELD,
        filters: MatchFilters = _FILTERS_FIELD,
    ) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = CheckAssetsRequest(assets=assets, filters=filters)
        return await _execute(
            accounts,
            state,
            "check_assets",
            len(assets),
            lambda: service.check_assets(request),
        )

    @server.tool(
        name="resolve_inventory",
        description="Resolve supplied inventory strings to canonical identities; input is never retained.",
        structured_output=True,
    )
    async def resolve_inventory(
        raw_strings: list[RawInventoryString] = _RAW_STRINGS_FIELD,
    ) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = ResolveRequest(raw_strings=raw_strings)
        return await _execute(
            accounts,
            state,
            "resolve_inventory",
            len(raw_strings),
            lambda: service.resolve_inventory(request),
        )

    @server.tool(
        name="get_fix_options",
        description="Return structured remediation targets and source links for a product version.",
        structured_output=True,
    )
    async def get_fix_options(
        vendor: str,
        product: str,
        version: str,
        advisory_id: str | None = None,
    ) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = GetFixOptionsRequest(
            vendor=vendor,
            product=product,
            version=version,
            advisory_id=advisory_id,
        )
        return await _execute(
            accounts,
            state,
            "get_fix_options",
            None,
            lambda: service.get_fix_options(request),
        )

    @server.tool(
        name="get_eol",
        description="Return structured end-of-life facts and source links for a product or model.",
        structured_output=True,
    )
    async def get_eol(
        vendor: str,
        model: str | None = None,
        os: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = GetEOLRequest(vendor=vendor, model=model, os=os, version=version)
        return await _execute(
            accounts,
            state,
            "get_eol",
            None,
            lambda: service.get_eol(request),
        )

    @server.tool(
        name="explain_verdict",
        description="Explain one defensive asset verdict with reasons, provenance, and source links.",
        structured_output=True,
    )
    async def explain_verdict(asset: Asset, advisory_id: str) -> dict[str, Any]:
        state = _current_request.get()
        if state is None:
            raise ToolError("request context unavailable")
        request = ExplainVerdictRequest(asset=asset, advisory_id=advisory_id)
        return await _execute(
            accounts,
            state,
            "explain_verdict",
            1,
            lambda: service.explain_verdict(request),
        )


def build_mcp_server(
    service: MCPService,
    accounts: MCPAccountGateway,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
) -> FastMCP:
    """Build the official SDK server using stateless Streamable HTTP."""

    server = FastMCP(
        "OSAK",
        instructions="OSAK returns compact, provenance-linked defensive advisory facts. Inventory is never retained.",
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=list(allowed_hosts)),
    )
    _register_tools(server, service, accounts)
    _harden_tool_validation(server)
    return server


def create_mcp_app(
    service: MCPService,
    accounts: MCPAccountGateway,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
) -> FastAPI:
    """Create a standalone app exposing MCP at exactly ``/mcp``."""

    app = FastAPI(title="OSAK MCP", docs_url=None, redoc_url=None, openapi_url=None)
    mount_mcp(app, service, accounts, allowed_hosts=allowed_hosts)
    return app


def mount_mcp(
    app: FastAPI,
    service: MCPService,
    accounts: MCPAccountGateway,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
) -> FastMCP:
    """Mount MCP after REST routes while reusing the same account gateway."""

    existing = getattr(app.state, "mcp_server", None)
    if existing is not None:
        return cast(FastMCP, existing)
    server = build_mcp_server(service, accounts, allowed_hosts=allowed_hosts)
    transport = _MCPAuthApp(server.streamable_http_app(), accounts)
    app.mount("/", transport)
    app.state.mcp_server = server
    original_lifespan = app.router.lifespan_context
    started = False

    @asynccontextmanager
    async def lifespan(target: FastAPI) -> AsyncIterator[None]:
        nonlocal started, server
        async with original_lifespan(target):
            # The SDK requires a fresh session manager for each ASGI startup.
            if started:
                server = build_mcp_server(service, accounts, allowed_hosts=allowed_hosts)
                transport.app = server.streamable_http_app()
                app.state.mcp_server = server
            started = True
            async with server.session_manager.run():
                yield

    app.router.lifespan_context = lifespan
    return server


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "MAX_ASSETS",
    "MCP_PATH",
    "CheckAssetsRequest",
    "ExplainVerdictRequest",
    "GetAdvisoryRequest",
    "GetEOLRequest",
    "GetFixOptionsRequest",
    "ListNewAdvisoriesRequest",
    "MCPAccountGateway",
    "MCPPrincipal",
    "MCPService",
    "MCPUsageMetadata",
    "QuotaDecision",
    "StaticAPIKeyAuth",
    "build_mcp_server",
    "create_mcp_app",
    "mount_mcp",
]
