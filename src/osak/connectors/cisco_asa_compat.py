"""Strict Cisco ASA compatibility-matrix connector.

The publisher table is treated as complete only when every expected header,
release row, and support marker is recognized.  A partial or ambiguous table
returns no platform map instead of manufacturing compatibility coverage.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx
from bs4 import BeautifulSoup

from osak.connectors.base import HealthStatus, RawDocument
from osak.connectors.common import ConnectorError, document_from_response, source_headers
from osak.connectors.oem_common import _catalog_records, _license, _provenance
from osak.core.models import CanonicalRecord, Product, Vendor

COMPATIBILITY_URL = "https://www.cisco.com/c/en/us/td/docs/security/asa/compatibility/asamatrx.html"

# The matrix enumerates individual chassis. Use the broader Software Checker
# family for each YES column. An exact fix must therefore cover that family.
_PLATFORM_HEADERS = {
    "asa virtual": "Cisco Adaptive Security Virtual Appliance (ASAv)",
    "firepower 1010 1010e 1120 1140 1150": "Cisco Firepower 1000 Series",
    "secure firewall 1210ce 1210cp 1220cx": "Cisco Secure Firewall 1200 Series",
    "secure firewall 1230 1240 1250": "Cisco Secure Firewall 1200 Series",
    "secure firewall 3105 3110 3120 3130 3140": "Cisco Secure Firewall 3100 Series",
    "firepower 4112 4115 4125 4145": "Cisco Firepower 4100 Series",
    "secure firewall 4215 4225 4245": "Cisco Secure Firewall 4200 Series",
    "firepower 9300": "Cisco Firepower 9000 Series",
    "isa 3000": "Cisco 3000 Series Industrial Security Appliances (ISA)",
}


def _cell_text(cell: Any) -> str:
    return " ".join(cell.get_text(" ", strip=True).split())


def _norm_header(value: str) -> str:
    return " ".join(value.casefold().split())


def _compatibility_table(soup: BeautifulSoup) -> tuple[list[str], list[list[str]]] | None:
    for table in soup.find_all("table"):
        caption = table.find("caption")
        caption_text = _norm_header(_cell_text(caption)) if caption is not None else ""
        if "asa and asdm compatibility: 9.23 and 9.22" not in caption_text:
            continue
        rows = table.find_all("tr")
        if len(rows) < 3:
            return None
        header_rows = [row.find_all(["th", "td"]) for row in rows[:2]]
        if len(header_rows[0]) != 3 or len(header_rows[1]) != 9:
            return None
        if [_norm_header(_cell_text(cell)) for cell in header_rows[0]][:2] != ["asa", "asdm"]:
            return None
        if _norm_header(_cell_text(header_rows[0][2])) != "asa model":
            return None
        headers = [_norm_header(_cell_text(cell)) for cell in header_rows[1]]
        if set(headers) != set(_PLATFORM_HEADERS):
            return None
        data: list[list[str]] = []
        for row in rows[2:]:
            cells = [_cell_text(cell) for cell in row.find_all(["th", "td"])]
            if not cells:
                continue
            if len(cells) != 11:
                return None
            if not cells[0].startswith("9.22(") and not cells[0].startswith("9.23("):
                return None
            markers = [cell.casefold() for cell in cells[2:]]
            if any(marker not in {"yes", "—", "-"} for marker in markers):
                return None
            data.append(cells)
        return headers, data
    return None


def parse_asa_compatibility(
    content: bytes,
    *,
    source: str,
    fetched_at: datetime,
    source_url: str,
    license_name: str,
) -> Product | None:
    """Parse a complete ASA 9.23/9.22 compatibility table into one Product."""

    soup = BeautifulSoup(content, "html.parser")
    parsed = _compatibility_table(soup)
    if parsed is None:
        return None
    headers, rows = parsed
    supported: dict[str, list[str]] = {}
    for row in rows:
        release = row[0]
        platforms = [
            _PLATFORM_HEADERS[header]
            for header, marker in zip(headers, row[2:], strict=True)
            if marker.casefold() == "yes"
        ]
        if not platforms or release in supported:
            return None
        supported[release] = list(dict.fromkeys(platforms))
    if not supported:
        return None
    catalog = _catalog_records(
        vendor_id="cisco",
        source=source,
        fetched_at=fetched_at,
        url=source_url,
        license_name=license_name,
        product_names=["ASA"],
    )
    product = next((item for item in catalog if isinstance(item, Product)), None)
    if product is None:
        return None
    return product.model_copy(
        update={
            "supported_platforms_by_release": supported,
            "provenance": [
                _provenance(
                    source=source,
                    fetched_at=fetched_at,
                    url=source_url,
                    license_name=license_name,
                    field="supported_platforms_by_release",
                )
            ],
        }
    )


class CiscoAsaCompatibilityConnector:
    id: ClassVar[str] = "cisco_asa_compatibility"
    vendor_scope: ClassVar[list[str]] = ["cisco"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "Cisco documentation availability"
    schedule: ClassVar[int] = 86400
    url: ClassVar[str] = COMPATIBILITY_URL

    def __init__(self, *, client: httpx.Client | None = None, timeout: float = 30.0) -> None:
        self.client = client or httpx.Client(headers=source_headers(), follow_redirects=True)
        self.timeout = timeout
        self.license = _license(
            "Cisco Support documentation terms pending",
            "https://developer.cisco.com/docs/support-apis/eox/",
            "Cisco ASA compatibility documentation; structured table facts and source link only.",
            "review",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        del since
        response = self.client.get(self.url, timeout=self.timeout)
        return [document_from_response(response)]

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        product = parse_asa_compatibility(
            raw.content,
            source=self.id,
            fetched_at=raw.fetched_at,
            source_url=raw.url,
            license_name=self.license.name,
        )
        if product is None:
            # A successful response whose matrix is changed or unusable is an
            # authoritative withdrawal for this source/field.  Transport and
            # HTTP failures never reach normalize because fetch raises first.
            catalog = _catalog_records(
                vendor_id="cisco",
                source=self.id,
                fetched_at=raw.fetched_at,
                url=raw.url,
                license_name=self.license.name,
                product_names=["ASA"],
            )
            vendor = next((item for item in catalog if isinstance(item, Vendor)), None)
            product = next((item for item in catalog if isinstance(item, Product)), None)
            if product is None:
                return [item for item in (vendor,) if item is not None]
            product = product.model_copy(
                update={
                    "supported_platforms_by_release": {},
                    "provenance": [
                        _provenance(
                            source=self.id,
                            fetched_at=raw.fetched_at,
                            url=raw.url,
                            license_name=self.license.name,
                            field="supported_platforms_by_release",
                        )
                    ],
                }
            )
            return [item for item in (vendor, product) if item is not None]
        catalog = _catalog_records(
            vendor_id="cisco",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
            product_names=[],
        )
        vendor = next((item for item in catalog if isinstance(item, Vendor)), None)
        return [item for item in (vendor, product) if item is not None]

    def healthcheck(self) -> HealthStatus:
        try:
            response = self.client.get(self.url, timeout=self.timeout)
            response.raise_for_status()
        except (httpx.HTTPError, ConnectorError) as exc:
            return HealthStatus(available=False, detail=f"Cisco ASA compatibility unavailable: {exc}")
        return HealthStatus(available=True, detail="Cisco ASA compatibility source reachable")
