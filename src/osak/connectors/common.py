"""Small HTTP and parsing helpers shared by the passive backbone connectors.

The helpers intentionally keep source documents as bytes.  Ingestion owns any
durable raw-store decision; the connectors only fetch and normalize advisory
facts.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, date, datetime
from typing import Any

import httpx

from osak.connectors.base import HealthStatus, RawDocument

USER_AGENT = "OSAK/0.1.0 (+https://osak.lab.scogo.ai)"
CANONICAL_VENDOR_IDS = frozenset({"cisco", "fortinet", "arista"})


def configured_vendor_scope() -> frozenset[str] | None:
    """Resolve the optional hosted vendor scope or reject invalid configuration."""
    raw = os.getenv("OSAK_VENDOR_SCOPE", "").strip()
    if not raw:
        return None
    values = frozenset(value.strip().casefold() for value in raw.split(","))
    if not values.issubset(CANONICAL_VENDOR_IDS):
        raise ValueError("OSAK_VENDOR_SCOPE must name cisco, fortinet, or arista")
    return values


class ConnectorError(RuntimeError):
    """A source could not be fetched or did not return a usable document."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC timestamp, accepting a naive UTC cursor for callers."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        return ensure_utc(datetime.fromisoformat(candidate))
    except ValueError:
        return None


def parse_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def parse_json(document: RawDocument) -> Any:
    try:
        return json.loads(document.content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"{document.url} did not contain valid JSON") from exc


def document_from_response(
    response: httpx.Response,
    *,
    url: str | None = None,
    fetched_at: datetime | None = None,
) -> RawDocument:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f"source returned HTTP {response.status_code}: {response.url}") from exc
    media_type = response.headers.get("content-type", "application/octet-stream").split(";", 1)[0]
    return RawDocument(
        url=url or str(response.url),
        fetched_at=ensure_utc(fetched_at or utc_now()),
        content=response.content,
        media_type=media_type,
    )


def healthcheck(
    client: httpx.Client,
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> HealthStatus:
    try:
        response = client.get(url, params=params, headers=headers or source_headers(), timeout=20)
        response.raise_for_status()
    except (httpx.HTTPError, ConnectorError) as exc:
        return HealthStatus(available=False, detail=str(exc))
    return HealthStatus(available=True, detail=f"HTTP {response.status_code}")


def slug(value: str | None, *, fallback: str = "unknown") -> str:
    if not value:
        return fallback
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized or fallback


def cve_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        return normalized
    return None


def as_float(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result


def source_headers(*, api_key: str | None = None) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers
