"""Request-scoped database loading for matching and inventory resolution.

The matching engine is intentionally database-free.  This adapter resolves a
request against the small product catalog once, then fetches only selected
products, their affected ranges, linked CVE enrichments, and EoL facts.  It
does not materialize the complete advisory corpus for a request.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from osak.core.db_models import (
    AdvisoryCVERow,
    AdvisoryRow,
    AffectedRangeRow,
    EnrichmentRow,
    EoLRecordRow,
    HardwareModelRow,
    ProductRow,
    SourceSyncStateRow,
    VendorRow,
)
from osak.core.models import (
    Advisory,
    AffectedRange,
    ClosedScopeEvidence,
    Condition,
    Dataset,
    Enrichment,
    EoLRecord,
    HardwareModel,
    MatchFilters,
    MatchRequest,
    MatchResponse,
    Product,
    Provenance,
    Remediation,
    ResolveRequest,
    ResolveResponse,
    SourceAvailability,
    Vendor,
    VersionRange,
)
from osak.match import match_assets, resolve_inventory


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _provenance(values: Iterable[dict[str, Any]] | None) -> list[Provenance]:
    return [Provenance.model_validate(item) for item in values or []]


def _vendor(row: VendorRow) -> Vendor:
    return Vendor(
        id=row.id,
        name=row.name,
        aliases=list(row.aliases or []),
        psirt_urls=list(row.psirt_urls or []),
        cna=row.cna,
        provenance=_provenance(row.provenance),
    )


def _product(row: ProductRow) -> Product:
    return Product(
        id=row.id,
        vendor_id=row.vendor_id,
        family=row.family,
        os=row.os,
        scheme=row.scheme,
        aliases=list(row.aliases or []),
        cpe_prefixes=list(row.cpe_prefixes or []),
        csaf_ids=list(row.csaf_ids or []),
        vendor_names=list(row.vendor_names or []),
        supported_platforms_by_release={
            release: list(platforms)
            for release, platforms in (row.supported_platforms_by_release or {}).items()
        },
        provenance=_provenance(row.provenance),
    )


def _hardware(row: HardwareModelRow) -> HardwareModel:
    return HardwareModel(
        id=row.id,
        vendor_id=row.vendor_id,
        product_id=row.product_id,
        family=row.family,
        aliases=list(row.aliases or []),
        provenance=_provenance(row.provenance),
    )


def _range(row: AffectedRangeRow) -> AffectedRange:
    return AffectedRange(
        advisory_id=row.advisory_id,
        product_id=row.product_id,
        versions=VersionRange.model_validate(row.versions),
        hardware_models=list(row.hardware_models or []),
        status=cast(Any, row.status),
        default_status=cast(Any, row.default_status),
        fixed_versions=list(row.fixed_versions or []),
        conditions=[Condition.model_validate(item) for item in row.conditions or []],
        provenance=_provenance(row.provenance),
    )


def _advisory(row: AdvisoryRow, ranges: list[AffectedRange]) -> Advisory:
    return Advisory(
        id=row.id,
        vendor_id=row.vendor_id,
        title=row.title,
        published=_aware(row.published),
        updated=_aware(row.updated),
        severity=cast(Any, row.severity),
        cvss=row.cvss,
        cves=list(row.cves or []),
        urls=list(row.urls or []),
        status=row.status,
        revisions=list(row.revisions or []),
        ranges=ranges,
        closed_scopes=[
            ClosedScopeEvidence.model_validate(item) for item in row.closed_scopes or []
        ],
        remediation=Remediation.model_validate(row.remediation) if row.remediation else None,
        provenance=_provenance(row.provenance),
    )


def _enrichment(row: EnrichmentRow) -> Enrichment:
    return Enrichment(
        cve_id=row.cve_id,
        kev=row.kev,
        kev_date=row.kev_date,
        ransomware=row.ransomware,
        epss=row.epss,
        percentile=row.percentile,
        epss_date=row.epss_date,
        cvss=row.cvss,
        cvss_version=row.cvss_version,
        cpes=list(row.cpes or []),
        provenance=_provenance(row.provenance),
    )


def _eol(row: EoLRecordRow) -> EoLRecord:
    return EoLRecord(
        id=row.id,
        vendor_id=row.vendor_id,
        product_id=row.product_id,
        model=row.model,
        version=row.version,
        eos=row.eos,
        end_maintenance=row.end_maintenance,
        end_security=row.end_security,
        last_support=row.last_support,
        provenance=_provenance(row.provenance),
    )


def _source_statuses(session: Session) -> list[SourceAvailability]:
    statuses: list[SourceAvailability] = []
    rows = session.scalars(select(SourceSyncStateRow).order_by(SourceSyncStateRow.source_id))
    for row in rows:
        metadata = row.metadata_json or {}
        if row.status == "success":
            state = "healthy"
        elif row.status == "failed" or row.status == "running":
            state = "unavailable"
        elif row.status == "idle":
            state = "never_synced"
        else:
            state = "disabled"
        kind = metadata.get("kind")
        if kind not in {"advisory", "enrichment", "eol"}:
            kind = None
        vendor_scope = metadata.get("vendor_scope", [])
        if not isinstance(vendor_scope, list) or not all(
            isinstance(vendor, str) and vendor for vendor in vendor_scope
        ):
            vendor_scope = []
        statuses.append(
            SourceAvailability(
                source_id=row.source_id,
                state=state,
                kind=kind,
                vendor_scope=vendor_scope,
                operator_excluded=bool(
                    metadata.get("operator_excluded", False)
                    or row.status == "disabled"
                    or metadata.get("allowed") is False
                ),
            )
        )
    return statuses


def load_catalog(session: Session) -> Dataset:
    """Load the vendor/product/model catalog once for identity resolution."""

    vendors = session.scalars(select(VendorRow).order_by(VendorRow.id))
    products = session.scalars(select(ProductRow).order_by(ProductRow.id))
    models = session.scalars(select(HardwareModelRow).order_by(HardwareModelRow.id))
    return Dataset(
        vendors=[_vendor(row) for row in vendors],
        products=[_product(row) for row in products],
        models=[_hardware(row) for row in models],
    )


_SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_scoped_dataset(
    session: Session,
    product_ids: set[str],
    filters: MatchFilters | None = None,
) -> Dataset:
    source_statuses = _source_statuses(session)
    unavailable_sources = [
        status.source_id
        for status in source_statuses
        if status.state != "healthy"
    ]
    if not product_ids:
        return Dataset(
            unavailable_sources=unavailable_sources,
            source_statuses=source_statuses,
        )

    ordered_product_ids = sorted(product_ids)
    product_rows = list(
        session.scalars(
            select(ProductRow)
            .where(ProductRow.id.in_(ordered_product_ids))
            .order_by(ProductRow.id)
        )
    )
    vendor_ids = sorted({row.vendor_id for row in product_rows})
    vendor_rows = list(
        session.scalars(select(VendorRow).where(VendorRow.id.in_(vendor_ids)).order_by(VendorRow.id))
    )
    model_rows = list(
        session.scalars(
            select(HardwareModelRow)
            .where(HardwareModelRow.product_id.in_(ordered_product_ids))
            .order_by(HardwareModelRow.id)
        )
    )

    candidate_advisory_ids = list(
        session.scalars(
            select(AffectedRangeRow.advisory_id)
            .where(AffectedRangeRow.product_id.in_(ordered_product_ids))
            .distinct()
        )
    )
    advisory_stmt = select(AdvisoryRow).where(AdvisoryRow.id.in_(candidate_advisory_ids))
    minimum_severity = filters.min_severity if filters is not None else None
    if minimum_severity is not None and minimum_severity != "unknown":
        minimum = _SEVERITY_ORDER[minimum_severity]
        allowed = [name for name, value in _SEVERITY_ORDER.items() if value >= minimum]
        advisory_stmt = advisory_stmt.where(AdvisoryRow.severity.in_(allowed))
    if filters is not None and filters.kev_only:
        kev_advisories = (
            select(AdvisoryCVERow.advisory_id)
            .join(EnrichmentRow, EnrichmentRow.cve_id == AdvisoryCVERow.cve_id)
            .where(EnrichmentRow.kev.is_(True))
        )
        advisory_stmt = advisory_stmt.where(AdvisoryRow.id.in_(kev_advisories))
    advisory_rows = (
        list(session.scalars(advisory_stmt.order_by(AdvisoryRow.id)))
        if candidate_advisory_ids
        else []
    )
    advisory_ids = [row.id for row in advisory_rows]
    range_rows = (
        list(
            session.scalars(
                select(AffectedRangeRow)
                .where(
                    AffectedRangeRow.product_id.in_(ordered_product_ids),
                    AffectedRangeRow.advisory_id.in_(advisory_ids),
                )
                .order_by(AffectedRangeRow.advisory_id, AffectedRangeRow.id)
            )
        )
        if advisory_ids
        else []
    )
    ranges_by_advisory: dict[str, list[AffectedRange]] = {}
    for row in range_rows:
        ranges_by_advisory.setdefault(row.advisory_id, []).append(_range(row))
    advisory_ids = sorted(ranges_by_advisory)

    cve_ids = (
        set(
            session.scalars(
                select(AdvisoryCVERow.cve_id).where(AdvisoryCVERow.advisory_id.in_(advisory_ids))
            )
        )
        if advisory_ids
        else set()
    )
    enrichment_rows = list(
        session.scalars(
            select(EnrichmentRow)
            .where(EnrichmentRow.cve_id.in_(sorted(cve_ids)))
            .order_by(EnrichmentRow.cve_id)
        )
    ) if cve_ids else []
    eol_rows = list(
        session.scalars(
            select(EoLRecordRow)
            .where(EoLRecordRow.product_id.in_(ordered_product_ids))
            .order_by(EoLRecordRow.id)
        )
    )

    return Dataset(
        vendors=[_vendor(row) for row in vendor_rows],
        products=[_product(row) for row in product_rows],
        models=[_hardware(row) for row in model_rows],
        advisories=[_advisory(row, ranges_by_advisory[row.id]) for row in advisory_rows],
        enrichments=[_enrichment(row) for row in enrichment_rows],
        eol=[_eol(row) for row in eol_rows],
        unavailable_sources=unavailable_sources,
        source_statuses=source_statuses,
    )


def load_matching_dataset(session: Session, payload: MatchRequest) -> Dataset:
    """Load only the DB facts needed by the resolved assets in *payload*."""

    catalog = load_catalog(session)
    catalog_response = match_assets(catalog, payload)
    product_ids = {
        result.product_id
        for result in catalog_response.results
        if result.status == "resolved" and result.product_id is not None
    }
    return _load_scoped_dataset(session, product_ids, payload.filters)


def match_request(session: Session, payload: MatchRequest) -> MatchResponse:
    """Resolve identities once, match against a request-scoped DB dataset."""

    catalog = load_catalog(session)
    catalog_response = match_assets(catalog, payload)
    product_ids = {
        result.product_id
        for result in catalog_response.results
        if result.status == "resolved" and result.product_id is not None
    }
    scoped_response = match_assets(
        _load_scoped_dataset(session, product_ids, payload.filters), payload
    )
    results = [
        catalog_result if catalog_result.status == "unresolved" else scoped_result
        for catalog_result, scoped_result in zip(catalog_response.results, scoped_response.results)
    ]
    return MatchResponse(results=results)


def resolve_request(session: Session, payload: ResolveRequest) -> ResolveResponse:
    """Resolve raw inventory using only the catalog; no advisory rows are read."""

    return resolve_inventory(load_catalog(session), payload)


__all__ = [
    "load_catalog",
    "load_matching_dataset",
    "match_request",
    "resolve_request",
]
