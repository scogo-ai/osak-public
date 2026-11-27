"""Cisco EoX and endoflife.date lifecycle connector implementations."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx

from osak.connectors.base import HealthStatus, RawDocument
from osak.connectors.oem_common import (
    ConnectorFetchError,
    _as_list,
    _as_mapping,
    _catalog_records,
    _HttpConnector,
    _json,
    _license,
    _parse_date,
    _provenance,
    _text,
)
from osak.core.models import CanonicalRecord, EoLRecord


class EndOfLifeDateConnector(_HttpConnector):
    id: ClassVar[str] = "endoflife_date_fortios"
    vendor_scope: ClassVar[list[str]] = ["fortinet"]
    kind: ClassVar[Literal["eol"]] = "eol"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "provider-defined"
    schedule: ClassVar[int] = 86400
    url: ClassVar[str] = "https://endoflife.date/api/v1/products/fortios/"

    def __init__(self, *, client: httpx.Client | None = None, timeout: float = 30.0) -> None:
        super().__init__(allowed_hosts={"endoflife.date"}, timeout=timeout, client=client)
        self.license = _license(
            "MIT",
            "https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE",
            "endoflife.date; MIT licensed lifecycle data, with source link attribution.",
            "facts",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        del since
        return [self._get(self.url, headers={"Accept": "application/json"})]

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = _json(raw.content)
        releases: list[Any]
        if isinstance(payload, list):
            releases = payload
        else:
            result = _as_mapping(payload.get("result")) or {}
            releases = _as_list(result.get("releases"))
        records: list[CanonicalRecord] = _catalog_records(
            vendor_id="fortinet",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
            product_names=["FortiOS"],
        )
        for release in releases:
            mapping = _as_mapping(release)
            if mapping is None:
                continue
            cycle = _text(mapping.get("cycle")) or _text(mapping.get("name"))
            if cycle is None:
                continue
            # v0 fields: support/eol. v1 fields: eoasFrom/eolFrom.
            maintenance = _parse_date(mapping.get("support") or mapping.get("eoasFrom"))
            last_support = _parse_date(mapping.get("eol") or mapping.get("eolFrom"))
            records.append(
                EoLRecord(
                    id=f"endoflife.date:fortios:{cycle}",
                    vendor_id="fortinet",
                    product_id="fortinet-fortios",
                    version=cycle,
                    end_maintenance=maintenance,
                    last_support=last_support,
                    provenance=[
                        _provenance(
                            source=self.id,
                            fetched_at=raw.fetched_at,
                            url=raw.url,
                            license_name=self.license.name,
                            field="eol",
                        )
                    ],
                )
            )
        return records

    def healthcheck(self) -> HealthStatus:
        try:
            document = self._get(self.url)
        except ConnectorFetchError as exc:
            return HealthStatus(available=False, detail=str(exc))
        return HealthStatus(available=bool(document.content), detail="endoflife.date FortiOS endpoint reachable")
