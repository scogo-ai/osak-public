"""Synchronous FastAPI application for OSAK REST endpoints."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from functools import cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from pydantic import AliasChoices, BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from osak.accounts.email import send_api_key_email
from osak.accounts.models import APIKey, UsageLog, User
from osak.accounts.service import (
    authenticate_key,
    create_key,
    create_user,
    finalize_usage,
    hash_api_key,
    hash_ip,
    record_usage,
    reserve_usage,
    revoke_key,
    rotate_key,
)
from osak.api.inventory import match_request as inventory_match_request
from osak.api.inventory import resolve_request as inventory_resolve_request
from osak.api.service import list_eol_records
from osak.connectors.base import Connector, SourceLicense, discover
from osak.core import repository as core_repository
from osak.core.db import SessionLocal
from osak.core.models import (
    Advisory,
    Change,
    EoLRecord,
    MatchRequest,
    MatchResponse,
    Product,
    ResolveRequest,
    ResolveResponse,
    SourceSyncState,
    Vendor,
)
from osak.ingest.types import ExportManifest

logger = logging.getLogger("osak.api")


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=256, validation_alias=AliasChoices("full_name", "name"))
    organization: str = Field(min_length=1, max_length=256)
    email: EmailStr
    turnstile_token: str | None = Field(
        default=None,
        max_length=4096,
        validation_alias=AliasChoices("turnstile_token", "turnstile"),
    )
    accept_terms: bool = False
    accepted_terms_version: str = Field(default="v1", min_length=1, max_length=64)


class AdminUserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=256)
    organization: str | None = Field(default=None, max_length=256)
    email: EmailStr
    verified: bool = True
    is_admin: bool = False
    plan: str = Field(default="free", max_length=64)
    requests_per_minute: int = Field(default=60, ge=1, le=1_000_000)
    requests_per_day: int = Field(default=10_000, ge=1, le=10_000_000)
    max_assets_per_request: int = Field(default=500, ge=1, le=100_000)


class AdminUserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str | None = Field(default=None, max_length=32)
    plan: str | None = Field(default=None, max_length=64)
    requests_per_minute: int | None = Field(default=None, ge=1, le=1_000_000)
    requests_per_day: int | None = Field(default=None, ge=1, le=10_000_000)
    max_assets_per_request: int | None = Field(default=None, ge=1, le=100_000)
    is_admin: bool | None = None


class AdminKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=64)
    environment: str | None = Field(default=None, pattern="^(live|test)$")
    label: str | None = Field(default=None, max_length=128)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    dataset_freshness: datetime | None = None
    sources: list[SourceSyncState] = Field(default_factory=list)


class SourcesResponse(BaseModel):
    sources: list[SourceStatusResponse] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)


class SourceStatusResponse(SourceSyncState):
    """Persisted sync state joined with discovered connector metadata."""

    license: SourceLicense | None = None
    schedule_seconds: int | None = None
    vendor_scope: list[str] = Field(default_factory=list)
    kind: str | None = None
    tier: str | None = None
    auth: str | None = None


class MessageResponse(BaseModel):
    message: str


class APIKeyResponse(BaseModel):
    api_key: str


class Problem(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None


PROBLEM_RESPONSES = {
    code: {
        "description": "RFC 9457 problem detail",
        "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}},
    }
    for code in (400, 401, 403, 404, 422, 429, 500, 503)
}


def _environment() -> str:
    return os.getenv("OSAK_ENV", "development").lower()


def _is_production() -> bool:
    return _environment() in {"production", "prod"}


def _database() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _problem(request: Request, status_code: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://osak.lab.scogo.ai/problems/{status_code}",
            "title": title,
            "status": status_code,
            "detail": detail,
            "instance": request.url.path,
        },
    )


def _safe_model(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_safe_model(item) for item in value]
    if isinstance(value, dict):
        return {key: _safe_model(item) for key, item in value.items()}
    return value


def match_assets(dataset: Any, request: MatchRequest) -> Any:
    """Delegate to the standalone deterministic matching library."""

    from osak.match import match_assets as implementation

    return implementation(dataset, request)


def resolve_inventory(dataset: Any, request: ResolveRequest) -> Any:
    """Delegate to the standalone inventory resolver."""

    from osak.match import resolve_inventory as implementation

    return implementation(dataset, request)


def _raw_api_key(request: Request) -> str | None:
    value = request.headers.get("x-api-key")
    if value:
        return value.strip()
    authorization = request.headers.get("authorization", "")
    scheme, _, credentials = authorization.partition(" ")
    if scheme.casefold() == "bearer" and credentials:
        return credentials.strip()
    return None


def _set_rate_headers(response: Response, quota: Any) -> None:
    for name, value in _rate_headers(quota).items():
        response.headers[name] = value


def _rate_headers(quota: Any) -> dict[str, str]:
    return {
        "RateLimit-Limit": str(quota.per_minute_limit),
        # This request itself consumes one slot, even though its usage row is
        # written after the endpoint returns.
        "RateLimit-Remaining": str(max(0, quota.remaining - 1)),
        "RateLimit-Reset": str(quota.reset_seconds),
    }


def _safe_user_agent(value: str | None) -> str | None:
    """Store only a stable digest; a caller-controlled UA may contain assets."""

    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest}"


def _redact_sensitive_query(scope: dict[str, Any]) -> None:
    """Redact token-like query values before a server access logger sees scope."""

    raw_query = scope.get("query_string", b"")
    if not raw_query:
        return
    safe_parts = []
    for part in raw_query.decode("latin-1").split("&"):
        key, _, _ = part.partition("=")
        if key.casefold() in {"token", "api_key", "apikey", "key", "secret"}:
            safe_parts.append(f"{key}=REDACTED")
        else:
            safe_parts.append(part)
    scope["query_string"] = "&".join(safe_parts).encode("latin-1")


def _require_auth(
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> APIKey:
    try:
        key = authenticate_key(session, _raw_api_key(request))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="authentication is not configured") from exc
    if key is None:
        raise HTTPException(status_code=401, detail="authentication required")
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    inventory_route = request.url.path in {"/api/v1/match", "/api/v1/resolve", "/mcp"}
    query_params = (
        {}
        if inventory_route
        else {
            name: request.query_params[name]
            for name in ("vendor", "product", "severity", "since")
            if name in request.query_params
        }
    )
    quota, reservation = reserve_usage(
        session,
        user=key.user,
        key=key,
        request_id=request_id,
        method=request.method,
        route=getattr(request.scope.get("route"), "path", request.url.path),
        query_params=query_params,
        user_agent=_safe_user_agent(request.headers.get("user-agent")),
        ip_hash=hash_ip(request.client.host if request.client else None),
    )
    _set_rate_headers(response, quota)
    request.state.auth = key
    request.state.usage_id = reservation.id
    if not quota.allowed:
        headers = _rate_headers(quota)
        headers["Retry-After"] = str(quota.reset_seconds)
        raise HTTPException(status_code=429, detail="quota exceeded", headers=headers)
    return key


def _trusted_admin_access(request: Request) -> None:
    """Accept the private assertion added by the Worker after validating Access."""
    secret = os.getenv("OSAK_ADMIN_ACCESS_TOKEN")
    if not secret:
        if not _is_production() and os.getenv("OSAK_DEV_ALLOW_ADMIN") == "1":
            return
        raise HTTPException(status_code=503, detail="Admin access is not configured")
    if not hmac.compare_digest(request.headers.get("x-osak-admin-access", ""), secret):
        raise HTTPException(status_code=403, detail="Trusted admin access required")


def _require_admin(
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> APIKey:
    key = _require_auth(request, response, session)
    if not key.user.is_admin:
        raise HTTPException(status_code=403, detail="admin access required")
    _trusted_admin_access(request)
    return key


def _verify_turnstile(token: str | None, remote_ip: str | None) -> None:
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not _is_production() and not secret:
        return
    if not secret or not token:
        raise HTTPException(status_code=503, detail="signup protection is not configured")
    try:
        response = httpx.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": secret, "response": token, "remoteip": remote_ip or ""},
            timeout=10,
        )
        response.raise_for_status()
        if not response.json().get("success", False):
            raise HTTPException(status_code=400, detail="signup protection failed")
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning("signup protection provider unavailable: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="signup protection unavailable") from exc


def _user_payload(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "full_name": user.full_name,
        "organization": user.organization,
        "email": user.email,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
        "status": user.status,
        "plan": user.plan,
        "requests_per_minute": user.requests_per_minute,
        "requests_per_day": user.requests_per_day,
        "max_assets_per_request": user.max_assets_per_request,
        "signup_key_sent_at": user.signup_key_sent_at,
        "is_admin": user.is_admin,
    }


app = FastAPI(
    title="OSAK",
    version="0.1.0",
    description="Open Security Advisory Kosh API",
    responses=PROBLEM_RESPONSES,
)


def _openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title="OSAK", version="0.1.0", description=app.description, routes=app.routes)
    schema.setdefault("components", {}).setdefault("schemas", {})["Problem"] = Problem.model_json_schema()
    schema.setdefault("components", {}).setdefault("securitySchemes", {}).update(
        {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "Example: `X-API-Key: osak_test_<one-time-seeded-key>`.",
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "Example: `Authorization: Bearer osak_test_<one-time-seeded-key>`.",
            },
            "CloudflareAccessClientId": {
                "type": "apiKey",
                "in": "header",
                "name": "CF-Access-Client-Id",
                "description": "Cloudflare Access service-token client ID required for admin routes; use the value provisioned to the trusted edge.",
            },
            "CloudflareAccessClientSecret": {
                "type": "apiKey",
                "in": "header",
                "name": "CF-Access-Client-Secret",
                "description": "Cloudflare Access service-token secret required for admin routes; never put this in a website request.",
            },
        }
    )
    public_paths = {
        "/api/v1/health",
        "/api/v1/sources",
        "/api/v1/signup",
    }
    for path, operations in schema.get("paths", {}).items():
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            operation.setdefault("description", operation.get("summary", "OSAK API operation"))
            operation.setdefault("responses", {}).update({str(code): model for code, model in PROBLEM_RESPONSES.items()})
            if path in public_paths:
                operation["security"] = []
            elif path.startswith("/api/v1/admin/"):
                operation["security"] = [
                    {
                        "ApiKeyAuth": [],
                        "CloudflareAccessClientId": [],
                        "CloudflareAccessClientSecret": [],
                    }
                ]
            else:
                operation["security"] = [{"ApiKeyAuth": []}, {"BearerAuth": []}]
            if operation["security"]:
                operation["description"] += (
                    "\n\nAuthentication example: `X-API-Key: osak_test_<one-time-seeded-key>` "
                    "or `Authorization: Bearer osak_test_<one-time-seeded-key>`."
                )
    parameter_examples = {
        "/api/v1/products": {"vendor": "fortinet", "page": 1},
        "/api/v1/advisories": {
            "vendor": "fortinet",
            "product": "fortinet-fortios",
            "since": "2026-01-01T00:00:00Z",
            "severity": "high",
            "kev": True,
            "cve": "CVE-2026-0001",
            "page": 1,
        },
        "/api/v1/advisories/{id}": {"id": "FG-IR-26-001"},
        "/api/v1/cves/{cve_id}": {"cve_id": "CVE-2026-0001"},
        "/api/v1/eol": {
            "vendor": "fortinet",
            "model": "FG-100F",
            "os": "fortios",
            "version": "7.2.5",
        },
        "/api/v1/changes": {
            "since": "2026-01-01T00:00:00Z",
            "after_sequence": 100,
            "limit": 100,
        },
        "/api/v1/datasets/files/{filename}": {
            "filename": f"dataset-{'0' * 64}.jsonl",
        },
        "/api/v1/admin/users": {"q": "fortinet"},
        "/api/v1/admin/users/{id}": {"id": "user-id-from-create-response"},
        "/api/v1/admin/keys/{id}": {"id": "key-id-from-create-response"},
        "/api/v1/admin/usage": {
            "user": "user-id",
            "key": "key-id",
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-02T00:00:00Z",
            "endpoint": "/api/v1/match",
        },
    }
    for path, examples in parameter_examples.items():
        for operation in schema.get("paths", {}).get(path, {}).values():
            if not isinstance(operation, dict):
                continue
            for parameter in operation.get("parameters", []):
                if parameter.get("name") in examples:
                    parameter["example"] = examples[parameter["name"]]

    request_examples = {
        "/api/v1/match": {
            "assets": [
                {
                    "asset_ref": "edge-01",
                    "vendor": "fortinet",
                    "product": "fortigate",
                    "version": "7.2.5",
                }
            ]
        },
        "/api/v1/resolve": {"raw_strings": ["Fortinet FortiOS Software, Version 7.2.5"]},
        "/api/v1/signup": {
            "name": "Ada Lovelace",
            "organization": "Analytical Engines",
            "email": "ada@example.test",
            "accept_terms": True,
        },
        "/api/v1/admin/users": {
            "full_name": "Ada Lovelace",
            "organization": "Analytical Engines",
            "email": "ada@example.test",
            "verified": True,
            "is_admin": False,
            "plan": "free",
            "requests_per_minute": 60,
            "requests_per_day": 10_000,
            "max_assets_per_request": 500,
        },
        "/api/v1/admin/users/{id}": {
            "status": "active",
            "plan": "free",
            "requests_per_minute": 60,
            "requests_per_day": 10_000,
            "max_assets_per_request": 500,
            "is_admin": False,
        },
        "/api/v1/admin/keys": {
            "user_id": "user-id-from-create-response",
            "environment": "test",
            "label": "local smoke key",
        },
    }
    for path, value in request_examples.items():
        operations = schema["paths"].get(path, {})
        for operation in operations.values():
            if isinstance(operation, dict) and "requestBody" in operation:
                content = operation["requestBody"].setdefault("content", {}).setdefault(
                    "application/json", {}
                )
                content["examples"] = {"example": {"summary": "Example request", "value": value}}
    app.openapi_schema = schema
    return schema


app.openapi = _openapi  # type: ignore[method-assign]


@app.exception_handler(RequestValidationError)
def _validation_exception(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default details echo ``input`` values; those may contain assets.
    safe_errors = [
        {"loc": list(error.get("loc", ())), "msg": error.get("msg", "invalid value"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return _problem(request, 422, "Validation error", "; ".join(error["msg"] for error in safe_errors))


@app.exception_handler(HTTPException)
def _http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "request failed"
    response = _problem(request, exc.status_code, "Request failed", detail)
    for name, value in (exc.headers or {}).items():
        response.headers[name] = value
    return response


@app.middleware("http")
async def request_metadata_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    started = time.perf_counter()
    request.state.request_id = str(uuid.uuid4())
    if _is_production():
        expected = os.getenv("OSAK_ORIGIN_SHARED_SECRET")
        supplied = request.headers.get("x-osak-origin-secret", "")
        if not expected:
            _redact_sensitive_query(request.scope)
            response = _problem(request, 503, "Origin guard unavailable", "origin guard is not configured")
            response.headers["X-Request-ID"] = request.state.request_id
            return response
        if not hmac.compare_digest(supplied, expected):
            _redact_sensitive_query(request.scope)
            response = _problem(request, 403, "Forbidden", "trusted origin required")
            response.headers["X-Request-ID"] = request.state.request_id
            return response
    if _is_production():
        # The authenticated Worker replaces this header from Cloudflare's client IP.
        edge_ip = request.headers.get("x-osak-client-ip")
        if edge_ip:
            try:
                request.scope["client"] = (str(ip_address(edge_ip)), 0)
            except ValueError:
                pass
    try:
        response = await call_next(request)
    except Exception as exc:  # noqa: BLE001
        # Do not let an exception traceback retain a parsed inventory object;
        # return a generic problem and log only the exception type.
        _redact_sensitive_query(request.scope)
        logger.warning("request handler failed: %s", type(exc).__name__)
        response = _problem(request, 500, "Internal server error", "request failed")
    response.headers["X-Request-ID"] = request.state.request_id
    auth = getattr(request.state, "auth", None)
    route_template = getattr(request.scope.get("route"), "path", "")
    if route_template.startswith("/api/v1/"):
        try:
            usage_session = SessionLocal()
            try:
                usage_id = getattr(request.state, "usage_id", None)
                if usage_id is not None:
                    finalize_usage(
                        usage_session,
                        usage_id,
                        status=response.status_code,
                        latency_ms=int((time.perf_counter() - started) * 1000),
                        response_size=int(response.headers.get("content-length", "0") or 0),
                        asset_count=getattr(request.state, "asset_count", None),
                        mcp_tool_name=getattr(request.state, "mcp_tool_name", None),
                    )
                elif auth is None:
                    record_usage(
                        usage_session, user=None, key=None, request_id=request.state.request_id,
                        method=request.method, route=route_template, status=response.status_code,
                        latency_ms=int((time.perf_counter() - started) * 1000),
                        response_size=int(response.headers.get("content-length", "0") or 0),
                        query_params={}, user_agent=request.headers.get("user-agent"),
                        ip_hash=hash_ip(request.client.host if request.client else None),
                    )
                usage_session.commit()
            finally:
                usage_session.close()
        except SQLAlchemyError as exc:
            # Usage logging must never turn a successful API call into a body
            # leak or a 500.  The failure itself contains no inventory data.
            logger.warning("usage metadata write failed: %s", type(exc).__name__)
    _redact_sensitive_query(request.scope)
    return response


@cache
def _source_catalog() -> dict[str, Connector]:
    return discover()


def _source_statuses(session: Session) -> list[SourceStatusResponse]:
    """Join persisted sync state with discovered connector metadata."""

    persisted = {state.source_id: state for state in core_repository.list_source_sync_states(session)}
    connectors = _source_catalog()
    results: list[SourceStatusResponse] = []
    for source_id, connector in sorted(connectors.items()):
        state = persisted.pop(source_id, None)
        results.append(
            SourceStatusResponse(
                source_id=source_id,
                status=state.status if state else "idle",
                last_started_at=state.last_started_at if state else None,
                last_attempt_at=state.last_attempt_at if state else None,
                last_success_at=state.last_success_at if state else None,
                cursor=state.cursor if state else None,
                error=state.error if state else None,
                records_seen=state.records_seen if state else 0,
                records_written=state.records_written if state else 0,
                metadata=state.metadata if state else {},
                license=connector.license,
                schedule_seconds=connector.schedule,
                vendor_scope=list(connector.vendor_scope),
                kind=connector.kind,
                tier=connector.tier,
                auth=connector.auth,
            )
        )
    for state in sorted(persisted.values(), key=lambda item: item.source_id):
        results.append(SourceStatusResponse.model_validate(state.model_dump()))
    return results


def _base_sync_state(value: SourceStatusResponse) -> SourceSyncState:
    return SourceSyncState.model_validate(value.model_dump(include=set(SourceSyncState.model_fields)))


@app.get("/api/v1/health", summary="Liveness and dataset freshness", response_model=HealthResponse)
def health(session: Session = Depends(_database)) -> HealthResponse:
    source_statuses = _source_statuses(session)
    successful = [state.last_success_at for state in source_statuses if state.last_success_at is not None]
    failed = [state for state in source_statuses if state.status in {"failed", "running"}]
    return HealthResponse(
        status="degraded" if failed else "ok",
        dataset_freshness=max(successful) if successful else None,
        sources=[_base_sync_state(state) for state in source_statuses],
    )


@app.get("/api/v1/sources", summary="Connector status and attribution", response_model=SourcesResponse)
def sources(session: Session = Depends(_database)) -> SourcesResponse:
    source_statuses = _source_statuses(session)
    return SourcesResponse(
        sources=source_statuses,
        unavailable=[state.source_id for state in source_statuses if state.status in {"failed", "running"}],
    )


@app.get("/api/v1/vendors", summary="List canonical vendors", response_model=list[Vendor])
def vendors(_: APIKey = Depends(_require_auth), session: Session = Depends(_database)) -> Any:
    return _safe_model(core_repository.list_vendors(session))


@app.get("/api/v1/products", summary="List canonical products", response_model=list[Product])
def products(
    vendor: str | None = None,
    page: int = Query(default=1, ge=1, description="Page number. Each page contains up to 100 products."),
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _safe_model(core_repository.list_products(session, vendor_id=vendor, page=page))


@app.get("/api/v1/advisories", summary="List normalized advisories", response_model=list[Advisory])
def advisories(
    vendor: str | None = None,
    product: str | None = None,
    since: datetime | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    cve: str | None = None,
    page: int = Query(default=1, ge=1),
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _safe_model(
        core_repository.list_advisories(
            session,
            vendor_id=vendor,
            product_id=product,
            since=since,
            severity=severity,
            kev=kev,
            cve_id=cve,
            page=page,
        )
    )


@app.get("/api/v1/advisories/{id}", summary="Get one advisory", response_model=Advisory)
def advisory(id: str, _: APIKey = Depends(_require_auth), session: Session = Depends(_database)) -> Any:
    value = core_repository.get_advisory(session, id)
    if value is None:
        raise HTTPException(status_code=404, detail="advisory not found")
    return _safe_model(value)


@app.get("/api/v1/cves/{cve_id}", summary="Get advisory by CVE", response_model=Advisory)
def cve(cve_id: str, _: APIKey = Depends(_require_auth), session: Session = Depends(_database)) -> Any:
    value = core_repository.get_advisory(session, cve_id)
    if value is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return _safe_model(value)


def _match_payload(session: Session, payload: MatchRequest, request: Request) -> Any:
    limit = getattr(request.state.auth.user, "max_assets_per_request", 500)
    if len(payload.assets) > limit:
        raise HTTPException(status_code=422, detail=f"at most {limit} assets are allowed")
    request.state.asset_count = len(payload.assets)
    return _safe_model(inventory_match_request(session, payload))


def _resolve_payload(session: Session, payload: ResolveRequest, request: Request) -> Any:
    request.state.asset_count = len(payload.raw_strings)
    return _safe_model(inventory_resolve_request(session, payload))


@app.post("/api/v1/match", summary="Correlate assets without retaining inventory", response_model=MatchResponse)
def match(
    payload: MatchRequest,
    request: Request,
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _match_payload(session, payload, request)


@app.post("/api/v1/resolve", summary="Resolve raw inventory without retaining inventory", response_model=ResolveResponse)
def resolve(
    payload: ResolveRequest,
    request: Request,
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _resolve_payload(session, payload, request)


@app.get("/api/v1/eol", summary="Get lifecycle records", response_model=list[EoLRecord])
def eol(
    vendor: str,
    model: str | None = None,
    os: str | None = None,
    version: str | None = None,
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _safe_model(
        list_eol_records(session, vendor=vendor, model=model, os=os, version=version)
    )


@app.get("/api/v1/changes", summary="Incremental advisory changes", response_model=list[Change])
def changes(
    since: datetime,
    after_sequence: int | None = Query(default=None, ge=0),
    limit: int = Query(default=1000, ge=1, le=10_000),
    _: APIKey = Depends(_require_auth),
    session: Session = Depends(_database),
) -> Any:
    return _safe_model(
        core_repository.list_changes(
            session,
            since=since,
            after_sequence=after_sequence,
            limit=limit,
        )
    )


def _export_directory() -> Path:
    return Path(os.environ.get("OSAK_DATA_DIR", "data")) / "exports"


@app.get("/api/v1/datasets/latest", summary="Latest dataset export manifest", response_model=ExportManifest)
def latest_dataset(_: APIKey = Depends(_require_auth)) -> ExportManifest:
    """Get the latest published snapshot, including its immutable download URL and SHA-256 digest."""
    try:
        return ExportManifest.model_validate_json((_export_directory() / "latest.json").read_bytes())
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="No dataset export has been published yet") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Dataset manifest is unreadable") from exc


@app.get("/api/v1/datasets/files/{filename}", summary="Download a checksummed advisory dataset",
         response_class=FileResponse, responses={200: {"content": {"application/x-ndjson": {}}}})
def download_dataset(filename: str, _: APIKey = Depends(_require_auth)) -> FileResponse:
    """Download the exact JSONL snapshot named in a published manifest."""
    if not re.fullmatch(r"dataset-[0-9a-f]{64}\.jsonl", filename):
        raise HTTPException(status_code=404, detail="Dataset does not exist")
    path = _export_directory() / filename
    if path.is_symlink() or not path.is_file():
        raise HTTPException(status_code=404, detail="Dataset does not exist")
    return FileResponse(path, media_type="application/x-ndjson", filename=filename)


@app.post("/api/v1/signup", summary="Request a one-time emailed API key", response_model=MessageResponse)
def signup(payload: SignupRequest, request: Request, session: Session = Depends(_database)) -> dict[str, str]:
    if not payload.accept_terms:
        raise HTTPException(status_code=400, detail="terms must be accepted")
    terms_version = os.getenv("OSAK_TERMS_VERSION", "v1")
    if payload.accepted_terms_version != terms_version:
        raise HTTPException(status_code=400, detail="terms version is not accepted")
    _verify_turnstile(payload.turnstile_token, request.client.host if request.client else None)
    normalized_email = str(payload.email).strip().lower()
    generic = {"message": "If eligible, your API key will be emailed."}
    existing = (
        session.query(User)
        .filter(func.lower(User.email) == normalized_email)
        .with_for_update()
        .first()
    )
    if existing is not None:
        active_key = (
            session.query(APIKey)
            .filter(APIKey.user_id == existing.id, APIKey.revoked_at.is_(None))
            .first()
        )
        if (
            active_key is not None
            or existing.is_admin
            or existing.status != "pending"
            or existing.email_verified
        ):
            session.rollback()
            return generic
    user = existing
    if user is None:
        try:
            user = create_user(
                session,
                full_name=payload.full_name,
                organization=payload.organization,
                email=normalized_email,
                verified=False,
                status="pending",
                signup_ip_hash=hash_ip(request.client.host if request.client else None),
                accepted_terms_version=terms_version,
            )
        except IntegrityError as exc:
            session.rollback()
            logger.warning("signup account race: %s", type(exc).__name__)
            return generic
        except SQLAlchemyError as exc:
            session.rollback()
            logger.warning("signup account persistence failed: %s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="signup is temporarily unavailable") from exc
    try:
        raw_key = create_key(session, user, environment=None)
        user.status = "active"
        user.email_verified = False
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        logger.warning("signup account race: %s", type(exc).__name__)
        return generic
    except SQLAlchemyError as exc:
        session.rollback()
        logger.warning("signup key persistence failed before delivery: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="signup is temporarily unavailable") from exc
    except ValueError as exc:
        session.rollback()
        raise HTTPException(status_code=503, detail="signup is temporarily unavailable") from exc

    try:
        delivered = send_api_key_email(email=user.email, raw_key=raw_key)
    except httpx.HTTPStatusError as exc:
        delivered = False if 400 <= exc.response.status_code < 500 else None
    except (httpx.HTTPError, OSError, ValueError, RuntimeError) as exc:
        logger.warning("signup key email outcome unknown: %s", type(exc).__name__)
        return generic
    if delivered is not True:
        if delivered is False:
            try:
                key = session.query(APIKey).filter(APIKey.key_hash == hash_api_key(raw_key)).one_or_none()
                if key is not None and key.revoked_at is None and key.last_used_at is None:
                    revoke_key(session, key)
                    user.status = "pending"
                    session.commit()
            except SQLAlchemyError as exc:
                session.rollback()
                logger.warning("signup rejection compensation failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="signup email is temporarily unavailable")

    try:
        user.signup_key_sent_at = datetime.now(UTC)
        session.commit()
    except SQLAlchemyError as exc:
        # The key and user were committed before delivery, so the emailed key
        # remains usable even if this bookkeeping update cannot be committed.
        session.rollback()
        logger.warning("signup delivery timestamp write failed: %s", type(exc).__name__)
    return generic


@app.get("/api/v1/signup/verify", include_in_schema=False, response_model=None)
def removed_signup_verify() -> None:
    """Legacy verification links are intentionally invalid after single-submit signup."""

    raise HTTPException(status_code=404, detail="signup verification is no longer supported")


@app.post("/api/v1/keys/rotate", summary="Rotate your API key", response_model=APIKeyResponse)
def keys_rotate(request: Request, response: Response, session: Session = Depends(_database)) -> APIKeyResponse:
    auth = _require_auth(request, response, session)
    raw_key = rotate_key(session, auth.user, environment=auth.environment)
    session.commit()
    return APIKeyResponse(api_key=raw_key)


@app.get("/api/v1/me", summary="Current account and usage")
def me(request: Request, response: Response, session: Session = Depends(_database)) -> dict[str, Any]:
    auth = _require_auth(request, response, session)
    usage = session.query(func.count(UsageLog.id)).filter(UsageLog.key_id == auth.id).scalar() or 0
    return {"user": _user_payload(auth.user), "key_prefix": auth.prefix, "usage": {"requests": int(usage)}}


@app.post("/api/v1/admin/users", summary="Create an account")
def admin_users_create(
    payload: AdminUserCreate,
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> dict[str, Any]:
    _require_admin(request, response, session)
    try:
        user = create_user(
            session,
            full_name=payload.full_name,
            organization=payload.organization,
            email=str(payload.email),
            verified=payload.verified,
            is_admin=payload.is_admin,
            requests_per_minute=payload.requests_per_minute,
            requests_per_day=payload.requests_per_day,
            max_assets_per_request=payload.max_assets_per_request,
        )
        user.plan = payload.plan
        session.commit()
    except (ValueError, SQLAlchemyError) as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _user_payload(user)


@app.get("/api/v1/admin/users", summary="List accounts")
def admin_users_list(
    request: Request,
    response: Response,
    q: str | None = None,
    session: Session = Depends(_database),
) -> list[dict[str, Any]]:
    _require_admin(request, response, session)
    query = session.query(User)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(User.email.ilike(pattern), User.full_name.ilike(pattern), User.organization.ilike(pattern)))
    return [_user_payload(user) for user in query.order_by(User.created_at).all()]


@app.patch("/api/v1/admin/users/{id}", summary="Update account")
def admin_users_patch(
    id: str,
    payload: AdminUserPatch,
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> dict[str, Any]:
    _require_admin(request, response, session)
    user = session.get(User, id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    for field in (
        "status",
        "plan",
        "requests_per_minute",
        "requests_per_day",
        "max_assets_per_request",
        "is_admin",
    ):
        value = getattr(payload, field)
        if value is not None:
            setattr(user, field, value)
    session.commit()
    return _user_payload(user)


@app.post("/api/v1/admin/keys", summary="Create a key for a user")
def admin_keys_create(
    payload: AdminKeyCreate,
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> dict[str, Any]:
    _require_admin(request, response, session)
    user = session.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    raw_key = create_key(session, user, environment=payload.environment, label=payload.label, allow_multiple=True)
    key = session.query(APIKey).filter(APIKey.key_hash == __import__("osak.accounts.service", fromlist=["hash_api_key"]).hash_api_key(raw_key)).one()
    session.commit()
    return {"id": key.id, "user_id": user.id, "prefix": key.prefix, "api_key": raw_key}


@app.delete("/api/v1/admin/keys/{id}", summary="Revoke a key")
def admin_keys_revoke(
    id: str,
    request: Request,
    response: Response,
    session: Session = Depends(_database),
) -> dict[str, str]:
    _require_admin(request, response, session)
    key = session.get(APIKey, id)
    if key is None:
        raise HTTPException(status_code=404, detail="key not found")
    revoke_key(session, key)
    session.commit()
    return {"status": "revoked"}


@app.get("/api/v1/admin/usage", summary="Query request metadata")
def admin_usage(
    request: Request,
    response: Response,
    user: str | None = None,
    key: str | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    endpoint: str | None = None,
    session: Session = Depends(_database),
) -> list[dict[str, Any]]:
    _require_admin(request, response, session)
    query = session.query(UsageLog)
    if user:
        query = query.filter(UsageLog.user_id == user)
    if key:
        query = query.filter(UsageLog.key_id == key)
    if from_:
        query = query.filter(UsageLog.timestamp >= from_)
    if to:
        query = query.filter(UsageLog.timestamp <= to)
    if endpoint:
        query = query.filter(UsageLog.route == endpoint)
    return [
        {
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
        for row in query.order_by(UsageLog.timestamp.desc()).all()
    ]


# Mount the concrete Streamable HTTP MCP server only after every REST route is
# registered, so its catch-all mount cannot shadow `/api`, `/docs`, or `/openapi.json`.
def _mount_mcp() -> None:
    from osak.mcp.integration import mount_accounts_mcp

    mount_accounts_mcp(app, session_factory=SessionLocal)


_mount_mcp()


__all__ = ["SessionLocal", "app"]
