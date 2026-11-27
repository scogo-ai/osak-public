"""Persistence and query helpers for the canonical OSAK dataset.

The repository keeps SQLAlchemy details behind small functions used by ingest and
the API.  Write helpers flush but do not commit: callers can atomically persist a
batch, its provenance, and its change events in one transaction.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import Select, and_, delete, exists, func, or_, select
from sqlalchemy.orm import Session, selectinload

from osak.connectors.base import RawDocument
from osak.core.db_models import (
    AdvisoryCVERow,
    AdvisoryRow,
    AffectedRangeRow,
    ChangeRow,
    ConflictRow,
    EnrichmentRow,
    EoLRecordRow,
    HardwareModelRow,
    ProductRow,
    ProvenanceRow,
    RawDocumentRow,
    RawObservationRow,
    SourceSyncStateRow,
    VendorRow,
)
from osak.core.models import (
    Advisory,
    AffectedRange,
    CanonicalRecord,
    Change,
    ClosedScopeEvidence,
    Condition,
    Conflict,
    Dataset,
    Enrichment,
    EoLRecord,
    HardwareModel,
    Product,
    Provenance,
    RawObservation,
    Remediation,
    SourceAvailability,
    SourceSyncState,
    Vendor,
    VersionRange,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """Normalize SQLite's timezone-naive return values to UTC-aware datetimes."""

    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _json(value: Any) -> Any:
    """Convert a Pydantic value into JSON-safe primitives."""

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _replace_provenance(
    session: Session,
    record_type: str,
    record_id: str,
    values: Iterable[Provenance | dict[str, Any]],
) -> None:
    session.execute(
        delete(ProvenanceRow).where(
            ProvenanceRow.record_type == record_type,
            ProvenanceRow.record_id == record_id,
        )
    )
    for value in values:
        item = value if isinstance(value, dict) else value.model_dump(mode="json")
        session.add(
            ProvenanceRow(
                record_type=record_type,
                record_id=record_id,
                field=item.get("field", "*"),
                source=item["source"],
                fetched_at=_as_required_datetime(item["fetched_at"]),
                url=item["url"],
                license=item["license"],
                confidence=item.get("confidence", "high"),
            )
        )


def _as_required_datetime(value: datetime | str) -> datetime:
    if isinstance(value, str):
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        value = datetime.fromisoformat(value)
    return _aware(value) or _utc_now()


def _ensure_vendor(session: Session, vendor_id: str, *, name: str | None = None) -> VendorRow:
    row = session.get(VendorRow, vendor_id)
    if row is None:
        row = VendorRow(id=vendor_id, name=name or vendor_id)
        session.add(row)
        session.flush()
    return row


def _ensure_product(
    session: Session,
    product_id: str,
    vendor_id: str,
    *,
    product: Product | None = None,
) -> ProductRow:
    _ensure_vendor(session, vendor_id)
    row = session.get(ProductRow, product_id)
    if row is None:
        if product is None:
            product = Product(
                id=product_id,
                vendor_id=vendor_id,
                family=product_id,
                os="unknown",
                scheme="unknown",
            )
        row = ProductRow(
            id=product.id,
            vendor_id=product.vendor_id,
            family=product.family,
            os=product.os,
            scheme=product.scheme,
        )
        session.add(row)
    elif product is not None:
        _copy_product(row, product)
    session.flush()
    return row


def _copy_vendor(row: VendorRow, record: Vendor) -> None:
    row.name = record.name
    row.aliases = list(record.aliases)
    row.psirt_urls = list(record.psirt_urls)
    row.cna = record.cna
    row.provenance = [_json(item) for item in record.provenance]


def _copy_product(row: ProductRow, record: Product) -> None:
    row.vendor_id = record.vendor_id
    row.family = record.family
    row.os = record.os
    row.scheme = record.scheme
    row.aliases = list(record.aliases)
    row.cpe_prefixes = list(record.cpe_prefixes)
    row.csaf_ids = list(record.csaf_ids)
    row.vendor_names = list(record.vendor_names)
    row.supported_platforms_by_release = {
        release: list(platforms)
        for release, platforms in record.supported_platforms_by_release.items()
    }
    row.provenance = [_json(item) for item in record.provenance]


def _copy_hardware(row: HardwareModelRow, record: HardwareModel) -> None:
    row.vendor_id = record.vendor_id
    row.product_id = record.product_id
    row.family = record.family
    row.aliases = list(record.aliases)
    row.provenance = [_json(item) for item in record.provenance]


def _copy_advisory(row: AdvisoryRow, record: Advisory) -> None:
    row.vendor_id = record.vendor_id
    row.title = record.title
    row.published = record.published
    row.updated = record.updated
    row.severity = record.severity
    row.cvss = record.cvss
    row.cves = list(record.cves)
    row.urls = list(record.urls)
    row.status = record.status
    row.revisions = list(record.revisions)
    row.closed_scopes = [_json(item) for item in record.closed_scopes]
    row.remediation = _json(record.remediation)
    row.provenance = [_json(item) for item in record.provenance]


def _copy_enrichment(row: EnrichmentRow, record: Enrichment) -> None:
    row.kev = record.kev
    row.kev_date = record.kev_date
    row.ransomware = record.ransomware
    row.epss = record.epss
    row.percentile = record.percentile
    row.epss_date = record.epss_date
    row.cvss = record.cvss
    row.cvss_version = record.cvss_version
    row.cpes = list(record.cpes)
    row.provenance = [_json(item) for item in record.provenance]


def _copy_eol(row: EoLRecordRow, record: EoLRecord) -> None:
    row.vendor_id = record.vendor_id
    row.product_id = record.product_id
    row.model = record.model
    row.version = record.version
    row.eos = record.eos
    row.end_maintenance = record.end_maintenance
    row.end_security = record.end_security
    row.last_support = record.last_support
    row.provenance = [_json(item) for item in record.provenance]


def _save_vendor(session: Session, record: Vendor) -> VendorRow:
    row = session.get(VendorRow, record.id)
    if row is None:
        row = VendorRow(id=record.id, name=record.name)
        session.add(row)
    _copy_vendor(row, record)
    session.flush()
    _replace_provenance(session, "vendor", record.id, record.provenance)
    return row


def _save_product(session: Session, record: Product) -> ProductRow:
    _ensure_vendor(session, record.vendor_id)
    row = session.get(ProductRow, record.id)
    if row is None:
        row = ProductRow(
            id=record.id,
            vendor_id=record.vendor_id,
            family=record.family,
            os=record.os,
            scheme=record.scheme,
        )
        session.add(row)
    _copy_product(row, record)
    session.flush()
    _replace_provenance(session, "product", record.id, record.provenance)
    return row


def _save_hardware(session: Session, record: HardwareModel) -> HardwareModelRow:
    _ensure_product(session, record.product_id, record.vendor_id)
    row = session.get(HardwareModelRow, record.id)
    if row is None:
        row = HardwareModelRow(
            id=record.id,
            vendor_id=record.vendor_id,
            product_id=record.product_id,
            family=record.family,
        )
        session.add(row)
    _copy_hardware(row, record)
    session.flush()
    _replace_provenance(session, "hardware_model", record.id, record.provenance)
    return row


def _save_advisory(session: Session, record: Advisory) -> AdvisoryRow:
    _ensure_vendor(session, record.vendor_id)
    for affected in record.ranges:
        _ensure_product(session, affected.product_id, record.vendor_id)
    row = session.get(AdvisoryRow, record.id)
    if row is None:
        row = AdvisoryRow(id=record.id, vendor_id=record.vendor_id, title=record.title)
        session.add(row)
        session.flush()
    _copy_advisory(row, record)
    row.ranges = [
        AffectedRangeRow(
            advisory_id=record.id,
            product_id=item.product_id,
            versions=_json(item.versions),
            hardware_models=list(item.hardware_models),
            status=item.status,
            default_status=item.default_status,
            fixed_versions=list(item.fixed_versions),
            conditions=[_json(condition) for condition in item.conditions],
            provenance=[_json(item_provenance) for item_provenance in item.provenance],
        )
        for item in record.ranges
    ]
    row.cve_links = [AdvisoryCVERow(advisory_id=record.id, cve_id=cve) for cve in record.cves]
    session.flush()
    _replace_provenance(session, "advisory", record.id, record.provenance)
    for index, item in enumerate(record.ranges):
        _replace_provenance(session, "affected_range", f"{record.id}:{index}", item.provenance)
    return row


def _save_enrichment(session: Session, record: Enrichment) -> EnrichmentRow:
    row = session.get(EnrichmentRow, record.cve_id)
    if row is None:
        row = EnrichmentRow(cve_id=record.cve_id)
        session.add(row)
    _copy_enrichment(row, record)
    session.flush()
    _replace_provenance(session, "enrichment", record.cve_id, record.provenance)
    return row


def _save_eol(session: Session, record: EoLRecord) -> EoLRecordRow:
    _ensure_product(session, record.product_id, record.vendor_id)
    row = session.get(EoLRecordRow, record.id)
    if row is None:
        row = EoLRecordRow(id=record.id, vendor_id=record.vendor_id, product_id=record.product_id)
        session.add(row)
    _copy_eol(row, record)
    session.flush()
    _replace_provenance(session, "eol", record.id, record.provenance)
    return row


_UNSET = object()


def save_canonical_record(
    session: Session,
    record: CanonicalRecord,
    *,
    source_id: str | None = None,
    record_change: bool = True,
    previous: CanonicalRecord | None | object = _UNSET,
    changed: bool | None = None,
) -> None:
    """Insert or replace a canonical record and preserve its source facts.

    Ingest already loads and locks the canonical record before merging it.  It
    may pass that ``previous`` record and the merger's ``changed`` result so a
    streaming replay does not perform a second identity load or write an
    unchanged row. Direct callers omit both arguments and retain the original
    change-detection behavior.
    """

    previous_record = (
        _existing_canonical_record(session, record)
        if previous is _UNSET
        else cast(CanonicalRecord | None, previous)
    )
    if previous_record is not None and previous_record.model_dump(mode="json") == record.model_dump(
        mode="json"
    ):
        return

    if isinstance(record, Vendor):
        _save_vendor(session, record)
        record_type = "vendor"
        record_id = record.id
    elif isinstance(record, Product):
        _save_product(session, record)
        record_type = "product"
        record_id = record.id
    elif isinstance(record, HardwareModel):
        _save_hardware(session, record)
        record_type = "hardware_model"
        record_id = record.id
    elif isinstance(record, Advisory):
        _save_advisory(session, record)
        record_type = "advisory"
        record_id = record.id
    elif isinstance(record, Enrichment):
        _save_enrichment(session, record)
        record_type = "enrichment"
        record_id = record.cve_id
    elif isinstance(record, EoLRecord):
        _save_eol(session, record)
        record_type = "eol"
        record_id = record.id
    else:
        raise TypeError(f"Unsupported canonical record: {type(record)!r}")

    if changed is None:
        changed = previous_record is None or previous_record.model_dump(
            mode="json"
        ) != record.model_dump(mode="json")
    if record_change and changed:
        if source_id is None:
            provenance_values = getattr(record, "provenance", [])
            source_id = provenance_values[0].source if provenance_values else None
        record_change_event(
            session,
            record_type=record_type,
            record_id=record_id,
            operation="upsert",
            source_id=source_id,
            payload=record.model_dump(mode="json"),
        )


def _existing_canonical_record(session: Session, record: CanonicalRecord) -> CanonicalRecord | None:
    """Load one persisted record for change-event deduplication.

    The save helpers intentionally remain replace/upsert oriented.  This small
    read lets repeated idempotent connector retries avoid emitting duplicate
    change events while still preserving the latest canonical row.
    """

    if isinstance(record, Vendor):
        vendor_row = session.get(VendorRow, record.id)
        return _vendor_from_row(vendor_row) if vendor_row else None
    if isinstance(record, Product):
        product_row = session.get(ProductRow, record.id)
        return _product_from_row(product_row) if product_row else None
    if isinstance(record, HardwareModel):
        hardware_row = session.get(HardwareModelRow, record.id)
        return _hardware_from_row(hardware_row) if hardware_row else None
    if isinstance(record, Advisory):
        return get_advisory(session, record.id)
    if isinstance(record, Enrichment):
        enrichment_row = session.get(EnrichmentRow, record.cve_id)
        return _enrichment_from_row(enrichment_row) if enrichment_row else None
    if isinstance(record, EoLRecord):
        eol_row = session.get(EoLRecordRow, record.id)
        return _eol_from_row(eol_row) if eol_row else None
    raise TypeError(f"Unsupported canonical record: {type(record)!r}")


def save_canonical_records(
    session: Session,
    records: Iterable[CanonicalRecord],
    *,
    source_id: str | None = None,
) -> int:
    """Persist a batch in the caller's transaction and return its size."""

    count = 0
    for record in records:
        save_canonical_record(session, record, source_id=source_id)
        count += 1
    return count


# Ingest workers historically call these operations "persist"; keep the
# explicit aliases so they can share one transaction without importing ORM rows.
persist_record = save_canonical_record
persist_records = save_canonical_records


def _vendor_from_row(row: VendorRow) -> Vendor:
    return Vendor(
        id=row.id,
        name=row.name,
        aliases=list(row.aliases or []),
        psirt_urls=list(row.psirt_urls or []),
        cna=row.cna,
        provenance=_provenance_from_json(row.provenance),
    )


def _product_from_row(row: ProductRow) -> Product:
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
        provenance=_provenance_from_json(row.provenance),
    )


def _hardware_from_row(row: HardwareModelRow) -> HardwareModel:
    return HardwareModel(
        id=row.id,
        vendor_id=row.vendor_id,
        product_id=row.product_id,
        family=row.family,
        aliases=list(row.aliases or []),
        provenance=_provenance_from_json(row.provenance),
    )


def _provenance_from_json(values: Iterable[dict[str, Any]] | None) -> list[Provenance]:
    return [Provenance.model_validate(item) for item in values or []]


def _advisory_from_row(row: AdvisoryRow) -> Advisory:
    ranges = [
        AffectedRange(
            advisory_id=item.advisory_id,
            product_id=item.product_id,
            versions=VersionRange.model_validate(item.versions),
            hardware_models=list(item.hardware_models or []),
            status=cast(Any, item.status),
            default_status=cast(Any, item.default_status),
            fixed_versions=list(item.fixed_versions or []),
            conditions=[Condition.model_validate(condition) for condition in item.conditions or []],
            provenance=_provenance_from_json(item.provenance),
        )
        for item in row.ranges
    ]
    remediation = Remediation.model_validate(row.remediation) if row.remediation else None
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
        remediation=remediation,
        provenance=_provenance_from_json(row.provenance),
    )


def _enrichment_from_row(row: EnrichmentRow) -> Enrichment:
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
        provenance=_provenance_from_json(row.provenance),
    )


def _eol_from_row(row: EoLRecordRow) -> EoLRecord:
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
        provenance=_provenance_from_json(row.provenance),
    )


def _advisory_select() -> Select[AdvisoryRow]:
    return select(AdvisoryRow).options(selectinload(AdvisoryRow.ranges))


def _source_availability(session: Session) -> list[SourceAvailability]:
    statuses: list[SourceAvailability] = []
    for row in session.scalars(select(SourceSyncStateRow).order_by(SourceSyncStateRow.source_id)):
        metadata = row.metadata_json or {}
        state = {
            "success": "healthy",
            "failed": "unavailable",
            "running": "unavailable",
            "idle": "never_synced",
            "disabled": "disabled",
        }.get(row.status, "unknown")
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


def load_dataset(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    product_ids: Sequence[str] | None = None,
    vendor_product_pairs: Sequence[tuple[str, str | None]] | None = None,
    advisory_ids: Sequence[str] | None = None,
    cve_id: str | None = None,
    since: datetime | None = None,
    limit: int | None = None,
) -> Dataset:
    """Load the complete dataset or a DB-filtered, request-scoped subset.

    Callers serving one API request should provide at least ``vendor_id`` or
    ``product_id``.  The unfiltered form remains useful for the offline export
    contract and tests, but no API query needs to materialize every advisory.
    """

    pair_vendor_ids = [pair_vendor for pair_vendor, _ in vendor_product_pairs or []]
    pair_product_ids = [
        pair_product for _, pair_product in vendor_product_pairs or [] if pair_product
    ]
    scoped_vendor_ids = list(
        dict.fromkeys(([vendor_id] if vendor_id else []) + list(vendor_ids or []) + pair_vendor_ids)
    )
    scoped_product_ids = list(
        dict.fromkeys(
            ([product_id] if product_id else []) + list(product_ids or []) + pair_product_ids
        )
    )
    advisory_stmt = _advisory_select()
    if vendor_product_pairs:
        pair_conditions = []
        for pair_vendor, pair_product in vendor_product_pairs:
            if pair_product is None:
                pair_conditions.append(AdvisoryRow.vendor_id == pair_vendor)
            else:
                pair_conditions.append(
                    and_(
                        AdvisoryRow.vendor_id == pair_vendor,
                        exists(
                            select(AffectedRangeRow.id).where(
                                AffectedRangeRow.advisory_id == AdvisoryRow.id,
                                AffectedRangeRow.product_id == pair_product,
                            )
                        ),
                    )
                )
        advisory_stmt = advisory_stmt.where(or_(*pair_conditions))
    elif scoped_vendor_ids:
        advisory_stmt = advisory_stmt.where(AdvisoryRow.vendor_id.in_(scoped_vendor_ids))
    if scoped_product_ids and not vendor_product_pairs:
        advisory_stmt = advisory_stmt.where(
            exists(
                select(AffectedRangeRow.id).where(
                    AffectedRangeRow.advisory_id == AdvisoryRow.id,
                    AffectedRangeRow.product_id.in_(scoped_product_ids),
                )
            )
        )
    if advisory_ids:
        advisory_stmt = advisory_stmt.where(AdvisoryRow.id.in_(list(advisory_ids)))
    if cve_id is not None:
        advisory_stmt = advisory_stmt.where(
            exists(
                select(AdvisoryCVERow.advisory_id).where(
                    AdvisoryCVERow.advisory_id == AdvisoryRow.id,
                    AdvisoryCVERow.cve_id == cve_id,
                )
            )
        )
    if since is not None:
        advisory_stmt = advisory_stmt.where(
            or_(AdvisoryRow.updated >= since, AdvisoryRow.published >= since)
        )
    advisory_stmt = advisory_stmt.order_by(AdvisoryRow.id)
    if limit is not None:
        advisory_stmt = advisory_stmt.limit(limit)
    advisory_rows = list(session.scalars(advisory_stmt).unique())
    selected_advisory_ids = [row.id for row in advisory_rows]

    vendor_stmt = select(VendorRow).order_by(VendorRow.id)
    if scoped_vendor_ids:
        vendor_stmt = vendor_stmt.where(VendorRow.id.in_(scoped_vendor_ids))
    elif scoped_product_ids:
        vendor_stmt = vendor_stmt.where(
            VendorRow.id.in_(
                select(ProductRow.vendor_id).where(ProductRow.id.in_(scoped_product_ids))
            )
        )
    elif selected_advisory_ids:
        vendor_stmt = vendor_stmt.where(
            VendorRow.id.in_(
                select(AdvisoryRow.vendor_id).where(AdvisoryRow.id.in_(selected_advisory_ids))
            )
        )
    vendor_rows = list(session.scalars(vendor_stmt))

    product_stmt = select(ProductRow).order_by(ProductRow.id)
    if scoped_vendor_ids:
        product_stmt = product_stmt.where(ProductRow.vendor_id.in_(scoped_vendor_ids))
    if scoped_product_ids:
        product_stmt = product_stmt.where(ProductRow.id.in_(scoped_product_ids))
    elif selected_advisory_ids:
        product_stmt = product_stmt.where(
            exists(
                select(AffectedRangeRow.id).where(
                    AffectedRangeRow.product_id == ProductRow.id,
                    AffectedRangeRow.advisory_id.in_(selected_advisory_ids),
                )
            )
        )
    product_rows = list(session.scalars(product_stmt))

    hardware_stmt = select(HardwareModelRow).order_by(HardwareModelRow.id)
    if scoped_vendor_ids:
        hardware_stmt = hardware_stmt.where(HardwareModelRow.vendor_id.in_(scoped_vendor_ids))
    if scoped_product_ids:
        hardware_stmt = hardware_stmt.where(HardwareModelRow.product_id.in_(scoped_product_ids))
    hardware_rows = list(session.scalars(hardware_stmt))

    enrichment_stmt = select(EnrichmentRow).order_by(EnrichmentRow.cve_id)
    if selected_advisory_ids:
        enrichment_stmt = enrichment_stmt.where(
            exists(
                select(AdvisoryCVERow.advisory_id).where(
                    AdvisoryCVERow.advisory_id.in_(selected_advisory_ids),
                    AdvisoryCVERow.cve_id == EnrichmentRow.cve_id,
                )
            )
        )
    elif cve_id:
        enrichment_stmt = enrichment_stmt.where(EnrichmentRow.cve_id == cve_id)
    enrichments = list(session.scalars(enrichment_stmt))

    eol_stmt = select(EoLRecordRow).order_by(EoLRecordRow.id)
    if scoped_vendor_ids:
        eol_stmt = eol_stmt.where(EoLRecordRow.vendor_id.in_(scoped_vendor_ids))
    if scoped_product_ids:
        eol_stmt = eol_stmt.where(EoLRecordRow.product_id.in_(scoped_product_ids))
    eol_rows = list(session.scalars(eol_stmt))

    source_statuses = _source_availability(session)
    unavailable = [status.source_id for status in source_statuses if status.state != "healthy"]
    return Dataset(
        vendors=[_vendor_from_row(row) for row in vendor_rows],
        products=[_product_from_row(row) for row in product_rows],
        models=[_hardware_from_row(row) for row in hardware_rows],
        advisories=[_advisory_from_row(row) for row in advisory_rows],
        enrichments=[_enrichment_from_row(row) for row in enrichments],
        eol=[_eol_from_row(row) for row in eol_rows],
        unavailable_sources=unavailable,
        source_statuses=source_statuses,
    )


def load_matching_dataset(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    product_ids: Sequence[str] | None = None,
    vendor_product_pairs: Sequence[tuple[str, str | None]] | None = None,
    advisory_ids: Sequence[str] | None = None,
) -> Dataset:
    """Load only records applicable to one or more matching assets.

    At least one scope selector is required, which prevents an accidental
    full-dataset materialization in a request handler.
    """

    if not any(
        (vendor_id, vendor_ids, product_id, product_ids, vendor_product_pairs, advisory_ids)
    ):
        raise ValueError("matching dataset requires an asset scope")

    return load_dataset(
        session,
        vendor_id=vendor_id,
        vendor_ids=vendor_ids,
        product_id=product_id,
        product_ids=product_ids,
        vendor_product_pairs=vendor_product_pairs,
        advisory_ids=advisory_ids,
    )


def load_dataset_subset(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    product_ids: Sequence[str] | None = None,
    vendor_product_pairs: Sequence[tuple[str, str | None]] | None = None,
    advisory_ids: Sequence[str] | None = None,
    cve_id: str | None = None,
    since: datetime | None = None,
    limit: int | None = None,
) -> Dataset:
    """Explicit name for callers that need a bounded, request-scoped dataset."""

    return load_dataset(
        session,
        vendor_id=vendor_id,
        vendor_ids=vendor_ids,
        product_id=product_id,
        product_ids=product_ids,
        vendor_product_pairs=vendor_product_pairs,
        advisory_ids=advisory_ids,
        cve_id=cve_id,
        since=since,
        limit=limit,
    )


def list_vendors(
    session: Session, *, query: str | None = None, page: int = 1, page_size: int = 100
) -> list[Vendor]:
    stmt = select(VendorRow).order_by(VendorRow.id)
    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(or_(VendorRow.id.ilike(pattern), VendorRow.name.ilike(pattern)))
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_vendor_from_row(row) for row in session.scalars(stmt)]


def get_vendor(session: Session, vendor_id: str) -> Vendor | None:
    row = session.get(VendorRow, vendor_id)
    return _vendor_from_row(row) if row else None


def list_products(
    session: Session,
    *,
    vendor_id: str | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[Product]:
    stmt = select(ProductRow).order_by(ProductRow.id)
    if vendor_id:
        stmt = stmt.where(ProductRow.vendor_id == vendor_id)
    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(or_(ProductRow.id.ilike(pattern), ProductRow.family.ilike(pattern)))
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_product_from_row(row) for row in session.scalars(stmt)]


def get_product(session: Session, product_id: str) -> Product | None:
    row = session.get(ProductRow, product_id)
    return _product_from_row(row) if row else None


_SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def list_advisories(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    since: datetime | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    cve_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[Advisory]:
    stmt = _advisory_select()
    if vendor_id:
        stmt = stmt.where(AdvisoryRow.vendor_id == vendor_id)
    elif vendor_ids:
        stmt = stmt.where(AdvisoryRow.vendor_id.in_(list(vendor_ids)))
    if product_id:
        stmt = stmt.where(
            exists(
                select(AffectedRangeRow.id).where(
                    AffectedRangeRow.advisory_id == AdvisoryRow.id,
                    AffectedRangeRow.product_id == product_id,
                )
            )
        )
    if since:
        stmt = stmt.where(or_(AdvisoryRow.updated >= since, AdvisoryRow.published >= since))
    if severity:
        minimum = _SEVERITY_ORDER.get(severity, 0)
        stmt = stmt.where(
            AdvisoryRow.severity.in_(
                [item for item, value in _SEVERITY_ORDER.items() if value >= minimum]
            )
        )
    if cve_id:
        stmt = stmt.where(
            exists(
                select(AdvisoryCVERow.advisory_id).where(
                    AdvisoryCVERow.advisory_id == AdvisoryRow.id,
                    AdvisoryCVERow.cve_id == cve_id,
                )
            )
        )
    if kev is not None:
        kev_condition = (
            select(AdvisoryCVERow.advisory_id)
            .join(EnrichmentRow, EnrichmentRow.cve_id == AdvisoryCVERow.cve_id)
            .where(
                AdvisoryCVERow.advisory_id == AdvisoryRow.id,
                EnrichmentRow.kev.is_(True),
            )
            .correlate(AdvisoryRow)
        )
        stmt = stmt.where(exists(kev_condition) if kev else ~exists(kev_condition))
    stmt = stmt.order_by(AdvisoryRow.updated.desc().nullslast(), AdvisoryRow.id)
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_advisory_from_row(row) for row in session.scalars(stmt).unique()]


def count_advisories(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    cve_id: str | None = None,
    since: datetime | None = None,
    severity: str | None = None,
    kev: bool | None = None,
) -> int:
    stmt = select(func.count(func.distinct(AdvisoryRow.id)))
    if vendor_id:
        stmt = stmt.where(AdvisoryRow.vendor_id == vendor_id)
    elif vendor_ids:
        stmt = stmt.where(AdvisoryRow.vendor_id.in_(list(vendor_ids)))
    if product_id:
        stmt = stmt.where(
            exists(
                select(AffectedRangeRow.id).where(
                    AffectedRangeRow.advisory_id == AdvisoryRow.id,
                    AffectedRangeRow.product_id == product_id,
                )
            )
        )
    if cve_id:
        stmt = stmt.join(AdvisoryCVERow, AdvisoryCVERow.advisory_id == AdvisoryRow.id).where(
            AdvisoryCVERow.cve_id == cve_id
        )
    if since:
        stmt = stmt.where(or_(AdvisoryRow.updated >= since, AdvisoryRow.published >= since))
    if severity:
        minimum = _SEVERITY_ORDER.get(severity.casefold(), 0)
        stmt = stmt.where(
            AdvisoryRow.severity.in_(
                [item for item, value in _SEVERITY_ORDER.items() if value >= minimum]
            )
        )
    if kev is not None:
        kev_condition = (
            select(AdvisoryCVERow.advisory_id)
            .join(EnrichmentRow, EnrichmentRow.cve_id == AdvisoryCVERow.cve_id)
            .where(
                AdvisoryCVERow.advisory_id == AdvisoryRow.id,
                EnrichmentRow.kev.is_(True),
            )
            .correlate(AdvisoryRow)
        )
        stmt = stmt.where(exists(kev_condition) if kev else ~exists(kev_condition))
    return int(session.scalar(stmt) or 0)


def get_advisory(session: Session, advisory_id_or_cve: str) -> Advisory | None:
    stmt = _advisory_select().where(AdvisoryRow.id == advisory_id_or_cve)
    row = session.scalars(stmt).unique().first()
    if row is None:
        stmt = (
            _advisory_select()
            .join(AdvisoryCVERow)
            .where(AdvisoryCVERow.cve_id == advisory_id_or_cve)
        )
        row = session.scalars(stmt).unique().first()
    return _advisory_from_row(row) if row else None


def list_eol(
    session: Session,
    *,
    vendor_id: str | None = None,
    vendor_ids: Sequence[str] | None = None,
    product_id: str | None = None,
    product_ids: Sequence[str] | None = None,
    model: str | None = None,
    version: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[EoLRecord]:
    stmt = select(EoLRecordRow).order_by(EoLRecordRow.id)
    if vendor_id:
        stmt = stmt.where(EoLRecordRow.vendor_id == vendor_id)
    elif vendor_ids:
        stmt = stmt.where(EoLRecordRow.vendor_id.in_(list(vendor_ids)))
    if product_id:
        stmt = stmt.where(EoLRecordRow.product_id == product_id)
    elif product_ids:
        stmt = stmt.where(EoLRecordRow.product_id.in_(list(product_ids)))
    if model:
        stmt = stmt.where(EoLRecordRow.model == model)
    if version:
        stmt = stmt.where(EoLRecordRow.version == version)
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_eol_from_row(row) for row in session.scalars(stmt)]


def store_raw_document(
    session: Session,
    raw: RawDocument,
    *,
    source_id: str | None = None,
) -> RawDocumentRow:
    """Insert a content-addressed raw source document exactly once."""

    content_hash = hashlib.sha256(raw.content).hexdigest()
    existing = session.get(RawDocumentRow, content_hash)
    if existing is not None:
        # A matching digest is the blob identity.  Never rewrite its bytes or
        # first-observation metadata; retain every later source observation.
        _record_raw_observation(session, existing, raw, source_id=source_id)
        return existing
    row = RawDocumentRow(
        content_hash=content_hash,
        source_id=source_id,
        url=raw.url,
        fetched_at=_as_required_datetime(raw.fetched_at),
        media_type=raw.media_type,
        content=raw.content,
    )
    session.add(row)
    session.flush()
    _record_raw_observation(session, row, raw, source_id=source_id)
    return row


def _record_raw_observation(
    session: Session,
    document: RawDocumentRow,
    raw: RawDocument,
    *,
    source_id: str | None,
) -> RawObservationRow:
    fetched_at = _as_required_datetime(raw.fetched_at)
    source_filter = (
        RawObservationRow.source_id.is_(None)
        if source_id is None
        else RawObservationRow.source_id == source_id
    )
    existing = session.scalar(
        select(RawObservationRow).where(
            RawObservationRow.content_hash == document.content_hash,
            source_filter,
            RawObservationRow.url == raw.url,
            RawObservationRow.fetched_at == fetched_at,
        )
    )
    if existing is not None:
        return existing
    observation = RawObservationRow(
        content_hash=document.content_hash,
        source_id=source_id,
        url=raw.url,
        fetched_at=fetched_at,
        media_type=raw.media_type,
    )
    session.add(observation)
    session.flush()
    return observation


def _raw_observation_from_row(row: RawObservationRow) -> RawObservation:
    return RawObservation(
        id=row.id,
        content_hash=row.content_hash,
        source_id=row.source_id,
        url=row.url,
        fetched_at=_aware(row.fetched_at) or _utc_now(),
        media_type=row.media_type,
    )


def list_raw_observations(
    session: Session,
    content_hash: str,
    *,
    source_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[RawObservation]:
    """List source observations without copying the raw blob into memory."""

    stmt = select(RawObservationRow).where(RawObservationRow.content_hash == content_hash)
    if source_id is not None:
        stmt = stmt.where(RawObservationRow.source_id == source_id)
    stmt = stmt.order_by(RawObservationRow.id).offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_raw_observation_from_row(row) for row in session.scalars(stmt)]


class RawStore:
    """Small adapter for workers that prefer an object over a free function."""

    def __init__(self, session: Session, source_id: str | None = None):
        self.session = session
        self.source_id = source_id

    def put(self, raw: RawDocument, *, source_id: str | None = None) -> RawDocumentRow:
        return store_raw_document(
            self.session,
            raw,
            source_id=source_id if source_id is not None else self.source_id,
        )


RawDocumentStore = RawStore


def upsert_source_sync_state(
    session: Session,
    source_id: str,
    *,
    status: str = "idle",
    last_started_at: datetime | None = None,
    last_attempt_at: datetime | None = None,
    last_success_at: datetime | None = None,
    cursor: str | None = None,
    error: str | None = None,
    records_seen: int = 0,
    records_written: int = 0,
    metadata: dict[str, Any] | None = None,
) -> SourceSyncState:
    row = session.get(SourceSyncStateRow, source_id)
    if row is None:
        row = SourceSyncStateRow(source_id=source_id)
        session.add(row)
    row.status = status
    row.last_started_at = last_started_at
    row.last_attempt_at = last_attempt_at
    row.last_success_at = last_success_at
    row.cursor = cursor
    row.error = error
    row.records_seen = records_seen
    row.records_written = records_written
    row.metadata_json = metadata or {}
    session.flush()
    return _sync_state_from_row(row)


def _sync_state_from_row(row: SourceSyncStateRow) -> SourceSyncState:
    return SourceSyncState(
        source_id=row.source_id,
        status=cast(Any, row.status),
        last_started_at=_aware(row.last_started_at),
        last_attempt_at=_aware(row.last_attempt_at),
        last_success_at=_aware(row.last_success_at),
        cursor=row.cursor,
        error=row.error,
        records_seen=row.records_seen,
        records_written=row.records_written,
        metadata=dict(row.metadata_json or {}),
    )


def list_source_sync_states(session: Session) -> list[SourceSyncState]:
    return [
        _sync_state_from_row(row)
        for row in session.scalars(
            select(SourceSyncStateRow).order_by(SourceSyncStateRow.source_id)
        )
    ]


def get_source_sync_state(session: Session, source_id: str) -> SourceSyncState | None:
    row = session.get(SourceSyncStateRow, source_id)
    return _sync_state_from_row(row) if row else None


def record_conflict(
    session: Session,
    *,
    record_type: str,
    record_id: str,
    field: str,
    winner_source: str,
    loser_source: str,
    winning_value: Any,
    losing_value: Any,
    detected_at: datetime | None = None,
    resolution: str | None = None,
) -> Conflict:
    row = ConflictRow(
        record_type=record_type,
        record_id=record_id,
        field=field,
        winner_source=winner_source,
        loser_source=loser_source,
        winning_value=_json(winning_value),
        losing_value=_json(losing_value),
        detected_at=_aware(detected_at) or _utc_now(),
        resolution=resolution,
    )
    session.add(row)
    session.flush()
    return _conflict_from_row(row)


def _conflict_from_row(row: ConflictRow) -> Conflict:
    return Conflict(
        id=row.id,
        record_type=row.record_type,
        record_id=row.record_id,
        field=row.field,
        winner_source=row.winner_source,
        loser_source=row.loser_source,
        winning_value=row.winning_value,
        losing_value=row.losing_value,
        detected_at=_aware(row.detected_at) or _utc_now(),
        resolution=row.resolution,
    )


def list_conflicts(
    session: Session,
    *,
    record_type: str | None = None,
    record_id: str | None = None,
    unresolved_only: bool = False,
    page: int = 1,
    page_size: int = 100,
) -> list[Conflict]:
    stmt = select(ConflictRow).order_by(ConflictRow.id)
    if record_type:
        stmt = stmt.where(ConflictRow.record_type == record_type)
    if record_id:
        stmt = stmt.where(ConflictRow.record_id == record_id)
    if unresolved_only:
        stmt = stmt.where(ConflictRow.resolution.is_(None))
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    return [_conflict_from_row(row) for row in session.scalars(stmt)]


def resolve_conflict(
    session: Session,
    conflict_id: int,
    *,
    resolution: str,
) -> Conflict | None:
    row = session.get(ConflictRow, conflict_id)
    if row is None:
        return None
    row.resolution = resolution
    session.flush()
    return _conflict_from_row(row)


def record_change_event(
    session: Session,
    *,
    record_type: str,
    record_id: str,
    operation: str,
    source_id: str | None = None,
    changed_at: datetime | None = None,
    payload: dict[str, Any] | None = None,
) -> Change:
    row = ChangeRow(
        record_type=record_type,
        record_id=record_id,
        operation=operation,
        source_id=source_id,
        changed_at=_aware(changed_at) or _utc_now(),
        payload=_json(payload),
    )
    session.add(row)
    session.flush()
    return _change_from_row(row)


# Short alias used by ingest code and tests.
record_change = record_change_event


def _change_from_row(row: ChangeRow) -> Change:
    return Change(
        sequence=row.sequence,
        record_type=row.record_type,
        record_id=row.record_id,
        operation=cast(Any, row.operation),
        source_id=row.source_id,
        changed_at=_aware(row.changed_at) or _utc_now(),
        payload=row.payload,
    )


def list_changes(
    session: Session,
    *,
    since: datetime | None = None,
    after_sequence: int | None = None,
    limit: int = 1000,
) -> list[Change]:
    stmt = select(ChangeRow).order_by(ChangeRow.sequence)
    if since:
        stmt = stmt.where(ChangeRow.changed_at >= since)
    if after_sequence is not None:
        stmt = stmt.where(ChangeRow.sequence > after_sequence)
    stmt = stmt.limit(limit)
    return [_change_from_row(row) for row in session.scalars(stmt)]
