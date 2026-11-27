"""Passive CISA Known Exploited Vulnerabilities enrichment connector."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import ClassVar, Literal

import httpx

from osak.connectors.base import HealthStatus, RawDocument, SourceLicense
from osak.connectors.common import (
    cve_id,
    document_from_response,
    healthcheck,
    parse_date,
    parse_json,
    source_headers,
)
from osak.core.models import CanonicalRecord, Enrichment, Provenance


class CisaKevConnector:
    id: ClassVar[str] = "cisa_kev"
    vendor_scope: ClassVar[list[str]] = ["*"]
    kind: ClassVar[Literal["enrichment"]] = "enrichment"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "Respect CISA feed availability"
    schedule: ClassVar[int] = 3600
    url: ClassVar[str] = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    license: ClassVar[SourceLicense] = SourceLicense(
        name="CISA Known Exploited Vulnerabilities Catalog",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        attribution="CISA Known Exploited Vulnerabilities Catalog",
        redistribution="facts",
    )

    def __init__(self, *, client: httpx.Client | None = None, timeout: float = 60) -> None:
        self.client = client or httpx.Client(headers=source_headers(), follow_redirects=True)
        self.timeout = timeout

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        # CISA publishes a complete catalog rather than a cursor endpoint.
        # Re-fetching it is idempotent and lets removals/metadata corrections
        # be observed by the merger.
        response = self.client.get(self.url, headers=source_headers(), timeout=self.timeout)
        yield self.document_from_response(response)

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = parse_json(raw)
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulnerabilities, list):
            return
        seen: set[str] = set()
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            identifier = cve_id(item.get("cveID"))
            if identifier is None or identifier in seen:
                continue
            seen.add(identifier)
            ransomware = item.get("knownRansomwareCampaignUse")
            yield Enrichment(
                cve_id=identifier,
                kev=True,
                kev_date=parse_date(item.get("dateAdded")),
                ransomware=str(ransomware) if ransomware is not None else None,
                epss=None,
                percentile=None,
                cvss=None,
                provenance=[self._provenance(raw)],
            )

    def healthcheck(self) -> HealthStatus:
        return healthcheck(self.client, self.url)

    def document_from_response(self, response: httpx.Response) -> RawDocument:
        return document_from_response(response, url=self.url)

    def _provenance(self, raw: RawDocument) -> Provenance:
        return Provenance(
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license=self.license.name,
            field="kev",
        )


KEVConnector = CisaKevConnector
