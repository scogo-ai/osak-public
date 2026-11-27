"""Dataset query and matching service functions shared by REST and MCP."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from osak.core.models import (
    Advisory,
    Asset,
    Dataset,
    EoLRecord,
    MatchFilters,
    MatchRequest,
    ResolveRequest,
)


def load_dataset(session: Any) -> Dataset:
    """Load the canonical dataset through the core repository boundary."""

    from osak.core.repository import load_dataset as repository_load_dataset

    loaded = repository_load_dataset(session)
    if loaded is None:
        raise RuntimeError("core repository returned no dataset")
    return loaded


def list_vendors(dataset: Dataset) -> list[Any]:
    return dataset.vendors


def list_products(dataset: Dataset, *, vendor: str | None = None) -> list[Any]:
    if not vendor:
        return dataset.products
    needle = vendor.casefold()
    return [
        product
        for product in dataset.products
        if needle in product.id.casefold()
        or needle == product.vendor_id.casefold()
        or needle in {alias.casefold() for alias in product.aliases}
    ]


_SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_at_least(actual: str, minimum: str) -> bool:
    return _SEVERITY_ORDER.get(actual.casefold(), 0) >= _SEVERITY_ORDER.get(minimum.casefold(), 0)


def _as_datetime(value: datetime | str) -> datetime:
    current = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _advisory_matches(
    advisory: Advisory,
    *,
    vendor: str | None = None,
    product: str | None = None,
    since: datetime | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    cve: str | None = None,
    enrichments: list[Any] | None = None,
) -> bool:
    if vendor and advisory.vendor_id.casefold() != vendor.casefold():
        return False
    if product and not any(product.casefold() in affected.product_id.casefold() for affected in advisory.ranges):
        return False
    if since:
        changed = advisory.updated or advisory.published
        if changed is None or _as_datetime(changed) <= since:
            return False
    if severity and not _severity_at_least(advisory.severity, severity):
        return False
    if cve and cve.casefold() not in {value.casefold() for value in advisory.cves}:
        return False
    if kev is not None:
        cve_ids = {value.casefold() for value in advisory.cves}
        is_kev = any(
            bool(enrichment.kev) and enrichment.cve_id.casefold() in cve_ids
            for enrichment in enrichments or []
        )
        if is_kev != kev:
            return False
    return True


def list_advisories(
    dataset: Dataset,
    *,
    vendor: str | None = None,
    product: str | None = None,
    since: datetime | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    cve: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[Advisory]:
    advisories = [
        advisory
        for advisory in dataset.advisories
        if _advisory_matches(
            advisory,
            vendor=vendor,
            product=product,
            since=since,
            severity=severity,
            kev=kev,
            cve=cve,
            enrichments=dataset.enrichments,
        )
    ]
    start = max(0, page - 1) * page_size
    return advisories[start : start + page_size]


def get_advisory(dataset: Dataset, advisory_id: str) -> Advisory | None:
    needle = advisory_id.casefold()
    for advisory in dataset.advisories:
        if advisory.id.casefold() == needle or needle in {cve.casefold() for cve in advisory.cves}:
            return advisory
    return None


def get_cve(dataset: Dataset, cve_id: str) -> Advisory | None:
    return get_advisory(dataset, cve_id)


def get_eol(
    dataset: Dataset,
    *,
    vendor: str,
    model: str | None = None,
    os: str | None = None,
    version: str | None = None,
) -> list[EoLRecord]:
    product_ids = {product.id.casefold() for product in list_products(dataset, vendor=vendor)}
    records = []
    for record in dataset.eol:
        if record.vendor_id.casefold() != vendor.casefold():
            continue
        if product_ids and record.product_id.casefold() not in product_ids:
            continue
        if model and record.model != model:
            continue
        if os and os.casefold() not in record.product_id.casefold():
            continue
        if version and record.version not in {None, version}:
            continue
        records.append(record)
    return records


def list_eol_records(
    session: Any,
    *,
    vendor: str,
    model: str | None = None,
    os: str | None = None,
    version: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[EoLRecord]:
    """Query lifecycle records with train-aware concrete-version matching."""

    from osak.core.db_models import ProductRow, VendorRow
    from osak.core.repository import list_eol as repository_list_eol
    from osak.match import eol_version_matches

    wanted = vendor.casefold().strip()
    vendor_ids = [
        row.id
        for row in session.scalars(select(VendorRow).order_by(VendorRow.id))
        if wanted in {row.id.casefold(), row.name.casefold(), *(alias.casefold() for alias in row.aliases or [])}
    ]
    if not vendor_ids:
        vendor_ids = [vendor]
    product_rows = list(
        session.scalars(
            select(ProductRow).where(ProductRow.vendor_id.in_(vendor_ids)).order_by(ProductRow.id)
        )
    )
    if os:
        os_needle = os.casefold().strip()
        product_rows = [
            row
            for row in product_rows
            if os_needle
            in {
                row.id.casefold(),
                row.os.casefold(),
                row.family.casefold(),
                *(alias.casefold() for alias in row.aliases or []),
                *(name.casefold() for name in row.vendor_names or []),
            }
        ]
    product_ids = [row.id for row in product_rows] if os else None
    if os and not product_ids:
        return []
    schemes = {row.id: row.scheme for row in product_rows}
    records = repository_list_eol(
        session,
        vendor_ids=vendor_ids,
        product_ids=product_ids,
        model=model,
        version=None,
        page=1,
        page_size=10_000,
    )
    if version:
        records = [
            record
            for record in records
            if eol_version_matches(
                schemes.get(
                    record.product_id,
                    "fortios"
                    if record.product_id.casefold().endswith("-fortios")
                    or (os and os.casefold() == "fortios")
                    else "",
                ),
                record.version,
                version,
            )
        ]
    start = max(0, page - 1) * page_size
    return records[start : start + page_size]


def match_request(session: Any, request: MatchRequest) -> Any:
    from osak.api.inventory import match_request as inventory_match_request

    return inventory_match_request(session, request)


def resolve_request(session: Any, request: ResolveRequest) -> Any:
    from osak.api.inventory import resolve_request as inventory_resolve_request

    return inventory_resolve_request(session, request)


def get_fix_options(
    session: Any,
    *,
    vendor: str,
    product: str,
    version: str,
    advisory_id: str | None = None,
) -> Any:
    request = MatchRequest(
        assets=[Asset(asset_ref="fix-options", vendor=vendor, product=product, version=version)],
        filters=MatchFilters(),
    )
    response = match_request(session, request)
    if advisory_id is None:
        return response
    if not response.results:
        return []
    return [finding for finding in response.results[0].findings if finding.advisory_id == advisory_id]


def explain_verdict(session: Any, *, asset: Asset, advisory_id: str) -> Any:
    response = match_request(session, MatchRequest(assets=[asset]))
    if not response.results:
        return None
    return next(
        (finding for finding in response.results[0].findings if finding.advisory_id == advisory_id),
        None,
    )


def list_new_advisories(
    dataset: Dataset,
    *,
    since: datetime,
    vendors: list[str] | None = None,
    min_severity: str | None = None,
) -> list[Advisory]:
    advisories = list_advisories(dataset, since=since, severity=min_severity)
    if vendors:
        wanted = {value.casefold() for value in vendors}
        advisories = [advisory for advisory in advisories if advisory.vendor_id.casefold() in wanted]
    return advisories


__all__ = [
    "explain_verdict",
    "get_advisory",
    "get_cve",
    "get_eol",
    "get_fix_options",
    "list_advisories",
    "list_eol_records",
    "list_new_advisories",
    "list_products",
    "list_vendors",
    "load_dataset",
    "match_request",
    "resolve_request",
]
