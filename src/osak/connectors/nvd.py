"""NVD 2.0 incremental CPE/CVSS enrichment connector.

NVD is intentionally not a source of advisory prose here.  Only the CVE id,
CVSS score/version, and CPE criteria are normalized.  Requests are paged with
``startIndex`` and paced according to the documented public limits; an API key
is sent only as a header and is never included in a persisted source URL.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta
from typing import Any, ClassVar, Literal

import httpx

from osak.connectors.base import HealthStatus, RawDocument, SourceLicense
from osak.connectors.common import (
    as_float,
    configured_vendor_scope,
    cve_id,
    document_from_response,
    ensure_utc,
    healthcheck,
    parse_json,
    source_headers,
    utc_now,
)
from osak.core.models import CanonicalRecord, Enrichment, Provenance


class NvdConnector:
    id: ClassVar[str] = "nvd"
    kind: ClassVar[Literal["enrichment"]] = "enrichment"
    tier: ClassVar[Literal["free"]] = "free"
    rate_limit: ClassVar[str] = "50 requests / 30 seconds with an API key; 5 without"
    schedule: ClassVar[int] = 900
    url: ClassVar[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    license: ClassVar[SourceLicense] = SourceLicense(
        name="NVD Terms of Use",
        url="https://nvd.nist.gov/developers/terms-of-use",
        attribution="National Institute of Standards and Technology National Vulnerability Database",
        redistribution="facts",
    )
    source_identifiers: ClassVar[dict[str, str]] = {
        "cisco": "psirt@cisco.com",
        "fortinet": "psirt@fortinet.com",
        "arista": "psirt@arista.com",
    }

    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        page_size: int = 2000,
        request_interval: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 60,
    ) -> None:
        if page_size < 1 or page_size > 2000:
            raise ValueError("NVD page_size must be between 1 and 2000")
        api_key = api_key or os.getenv("NVD_API_KEY")
        self.api_key = api_key
        self.auth: Literal["none", "api_key"] = "api_key" if api_key else "none"
        self.client = client or httpx.Client(
            headers=source_headers(api_key=api_key), follow_redirects=False
        )
        self.page_size = page_size
        self.request_interval = (
            request_interval
            if request_interval is not None
            else (0.61 if api_key else 6.1)
        )
        if self.request_interval < 0:
            raise ValueError("request_interval cannot be negative")
        self.sleep = sleep
        self.clock = clock
        self.timeout = timeout
        self._last_request: float | None = None
        self.scope = configured_vendor_scope()
        self.vendor_scope = sorted(self.scope) if self.scope else ["*"]

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        source_identifiers = (
            [self.source_identifiers[vendor] for vendor in self.vendor_scope]
            if self.scope
            else [None]
        )
        end = utc_now()
        if since is None:
            for identifier in source_identifiers:
                yield from self._fetch_window(None, end, identifier)
            return
        start = ensure_utc(since)
        if start > end:
            raise ValueError("NVD since cursor cannot be in the future")
        # NVD rejects modification windows larger than 120 days.  Overlap
        # adjacent windows by one second so a boundary update cannot be lost;
        # canonical enrichment upserts make the replay harmless.
        maximum_window = timedelta(days=119, hours=23, minutes=59, seconds=59)
        window_start = start
        while True:
            window_end = min(window_start + maximum_window, end)
            for identifier in source_identifiers:
                yield from self._fetch_window(window_start, window_end, identifier)
            if window_end >= end:
                break
            window_start = window_end - timedelta(seconds=1)

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = parse_json(raw)
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulnerabilities, list):
            return
        seen: set[str] = set()
        for wrapper in vulnerabilities:
            if not isinstance(wrapper, dict):
                continue
            cve = wrapper.get("cve")
            if not isinstance(cve, dict):
                continue
            identifier = cve_id(cve.get("id"))
            if identifier is None or identifier in seen:
                continue
            seen.add(identifier)
            score, version = self._cvss(cve.get("metrics"))
            # NVD 2.0 places configurations inside the CVE object.  The
            # wrapper itself only contains the CVE and must not be treated as
            # an applicability source.
            cpes = self._cpes(cve.get("configurations"))
            yield Enrichment(
                cve_id=identifier,
                epss=None,
                percentile=None,
                cvss=score,
                cvss_version=version,
                cpes=cpes,
                provenance=[self._provenance(raw)],
            )

    def healthcheck(self) -> HealthStatus:
        return healthcheck(
            self.client,
            self.url,
            params={"resultsPerPage": "1"},
            headers=source_headers(api_key=self.api_key),
        )

    def document_from_response(self, response: httpx.Response) -> RawDocument:
        return document_from_response(response)

    def _fetch_window(
        self,
        start: datetime | None,
        end: datetime,
        source_identifier: str | None = None,
    ) -> Iterator[RawDocument]:
        start_index = 0
        total: int | None = None
        while total is None or start_index < total:
            params = {
                "startIndex": str(start_index),
                "resultsPerPage": str(self.page_size),
            }
            if start is not None:
                params["lastModStartDate"] = self._nvd_timestamp(start)
                params["lastModEndDate"] = self._nvd_timestamp(end)
            if source_identifier is not None:
                params["sourceIdentifier"] = source_identifier
            self._pace()
            response = self.client.get(
                self.url,
                params=params,
                headers=source_headers(api_key=self.api_key),
                timeout=self.timeout,
            )
            document = self.document_from_response(response)
            yield document.model_copy(update={"fetched_at": end})
            payload = parse_json(document)
            if not isinstance(payload, dict):
                raise TypeError("NVD response is not an object")
            vulnerabilities = payload.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise TypeError("NVD response did not include vulnerabilities")
            total = self._integer(payload.get("totalResults"))
            if total is None:
                total = start_index + len(vulnerabilities)
            if not vulnerabilities:
                if start_index < total:
                    raise RuntimeError("NVD returned an empty page before totalResults")
                break
            start_index += len(vulnerabilities)
            if start_index >= total:
                break

    def _pace(self) -> None:
        if self._last_request is None or self.request_interval == 0:
            self._last_request = self.clock()
            return
        elapsed = self.clock() - self._last_request
        remaining = self.request_interval - elapsed
        if remaining > 0:
            self.sleep(remaining)
        self._last_request = self.clock()

    @staticmethod
    def _nvd_timestamp(value: datetime) -> str:
        return ensure_utc(value).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    @staticmethod
    def _integer(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError):
            return None
        return result if result >= 0 else None

    @staticmethod
    def _cvss(metrics: Any) -> tuple[float | None, str | None]:
        if not isinstance(metrics, dict):
            return None, None
        for key in ("cvssMetricV40", "cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("cvssData")
                if not isinstance(data, dict):
                    continue
                score = as_float(data.get("baseScore"))
                if score is not None and 0 <= score <= 10:
                    version = data.get("version")
                    return score, str(version) if version is not None else None
        return None, None

    @staticmethod
    def _cpes(configurations: Any) -> list[str]:
        found: list[str] = []

        def walk(value: Any, negated: bool = False) -> None:
            if isinstance(value, dict):
                node_negated = negated or value.get("negate", False) is True
                criteria = value.get("criteria")
                if (
                    not node_negated
                    and isinstance(criteria, str)
                    and criteria
                    and value.get("vulnerable") is True
                ):
                    found.append(criteria)
                for child in value.values():
                    if isinstance(child, (dict, list)):
                        walk(child, node_negated)
            elif isinstance(value, list):
                for child in value:
                    walk(child, negated)

        walk(configurations)
        return list(dict.fromkeys(found))

    def _provenance(self, raw: RawDocument) -> Provenance:
        return Provenance(
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license=self.license.name,
            field="cvss/cpes",
        )


NVDConnector = NvdConnector
