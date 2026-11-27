"""FIRST EPSS daily-score connector."""

from __future__ import annotations

import csv
import gzip
import io
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx

from osak.connectors.base import HealthStatus, RawDocument, SourceLicense
from osak.connectors.common import (
    as_float,
    configured_vendor_scope,
    cve_id,
    document_from_response,
    healthcheck,
    parse_date,
    parse_datetime,
    parse_json,
    source_headers,
)
from osak.core.models import CanonicalRecord, Enrichment, Provenance


class FirstEpssConnector:
    id: ClassVar[str] = "first_epss"
    kind: ClassVar[Literal["enrichment"]] = "enrichment"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "FIRST public API limits apply"
    schedule: ClassVar[int] = 86400
    url: ClassVar[str] = "https://api.first.org/data/v1/epss"
    bulk_url: ClassVar[str] = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    license: ClassVar[SourceLicense] = SourceLicense(
        name="FIRST EPSS data terms",
        url="https://www.first.org/epss/data",
        attribution="FIRST EPSS",
        redistribution="facts",
    )

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        api_batch_size: int = 100,
        timeout: float = 60,
    ) -> None:
        if api_batch_size < 1:
            raise ValueError("api_batch_size must be positive")
        self.client = client or httpx.Client(headers=source_headers(), follow_redirects=True)
        self.api_batch_size = api_batch_size
        self.timeout = timeout
        scope = configured_vendor_scope()
        self.vendor_scope = sorted(scope) if scope else ["*"]

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        """Fetch the complete daily score file for scheduled refreshes."""

        response = self.client.get(self.bulk_url, headers=source_headers(), timeout=self.timeout)
        yield self.document_from_response(response)

    def fetch_for_cves(self, identifiers: Sequence[str]) -> Iterable[RawDocument]:
        """Fetch bounded scores for cache misses or on-demand lookups."""

        normalized = list(
            dict.fromkeys(
                identifier
                for identifier in (cve_id(value) for value in identifiers)
                if identifier
            )
        )
        for start in range(0, len(normalized), self.api_batch_size):
            batch = normalized[start : start + self.api_batch_size]
            response = self.client.get(
                self.url,
                params={"cve": ",".join(batch)},
                headers=source_headers(),
                timeout=self.timeout,
            )
            yield self.document_from_response(response)

    fetch_cves = fetch_for_cves

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        if self._is_csv(raw):
            yield from self._normalize_csv(raw)
            return
        payload = parse_json(raw)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return
        yield from self._normalize_rows(data, raw, score_date=None)

    def healthcheck(self) -> HealthStatus:
        return healthcheck(self.client, self.url, params={"limit": "1", "offset": "0"})

    def document_from_response(self, response: httpx.Response) -> RawDocument:
        return document_from_response(response)

    @staticmethod
    def _is_csv(raw: RawDocument) -> bool:
        return (
            raw.content.startswith(b"#")
            or raw.content.startswith(b"cve,")
            or raw.content.startswith(b"\x1f\x8b")
        )

    def _normalize_csv(self, raw: RawDocument) -> Iterator[CanonicalRecord]:
        content = gzip.decompress(raw.content) if raw.content.startswith(b"\x1f\x8b") else raw.content
        text = content.decode("utf-8-sig")
        score_date = None
        lines = text.splitlines()
        if lines and lines[0].startswith("#"):
            marker = lines.pop(0)
            _, _, value = marker.partition("score_date:")
            score_date = parse_datetime(value.strip()) if value else None
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        yield from self._normalize_rows(reader, raw, score_date=score_date.date() if score_date else None)

    def _normalize_rows(
        self,
        rows: Iterable[dict[str, Any]],
        raw: RawDocument,
        *,
        score_date: Any,
    ) -> Iterator[CanonicalRecord]:
        seen: set[str] = set()
        for item in rows:
            if not isinstance(item, dict):
                continue
            identifier = cve_id(item.get("cve"))
            if identifier is None or identifier in seen:
                continue
            epss = as_float(item.get("epss"))
            percentile = as_float(item.get("percentile"))
            if epss is not None and not 0 <= epss <= 1:
                epss = None
            if percentile is not None and not 0 <= percentile <= 1:
                percentile = None
            seen.add(identifier)
            yield Enrichment(
                cve_id=identifier,
                cvss=None,
                epss=epss,
                percentile=percentile,
                epss_date=parse_date(item.get("date")) or score_date,
                provenance=[self._provenance(raw)],
            )

    def _provenance(self, raw: RawDocument) -> Provenance:
        return Provenance(
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license=self.license.name,
            field="epss",
        )


EPSSConnector = FirstEpssConnector
