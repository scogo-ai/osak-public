from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from osak.api.inventory import (
    load_matching_dataset,
    match_request,
    resolve_request,
)
from osak.core.db import Base
from osak.core.db_models import (
    AdvisoryRow,
    AffectedRangeRow,
    EnrichmentRow,
    EoLRecordRow,
)
from osak.core.models import (
    Advisory,
    AffectedRange,
    Asset,
    Enrichment,
    EoLRecord,
    MatchRequest,
    Product,
    ResolveRequest,
    Vendor,
    VersionRange,
)
from osak.core.repository import save_canonical_record, upsert_source_sync_state

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def make_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def seed(session: Session) -> None:
    for vendor in (
        Vendor(id="fortinet", name="Fortinet"),
        Vendor(id="cisco", name="Cisco"),
    ):
        save_canonical_record(session, vendor)
    for product in (
        Product(
            id="fortigate",
            vendor_id="fortinet",
            family="FortiGate",
            os="fortios",
            scheme="fortios",
            aliases=["FortiOS"],
        ),
        Product(
            id="fortigate-other",
            vendor_id="fortinet",
            family="FortiManager",
            os="fortimanager",
            scheme="fortios",
        ),
        Product(
            id="cisco-iosxe",
            vendor_id="cisco",
            family="IOS XE",
            os="iosxe",
            scheme="cisco_iosxe",
            aliases=["IOS XE"],
        ),
    ):
        save_canonical_record(session, product)
    for advisory in (
        Advisory(
            id="FG-RELEVANT",
            vendor_id="fortinet",
            title="Relevant Fortinet advisory",
            cves=["CVE-F-1"],
            ranges=[
                AffectedRange(
                    advisory_id="FG-RELEVANT",
                    product_id="fortigate",
                    versions=VersionRange(train="7.2", upper="7.2.8"),
                    status="affected",
                    fixed_versions=["7.2.8"],
                )
            ],
        ),
        Advisory(
            id="FG-UNRELATED",
            vendor_id="fortinet",
            title="Unrelated Fortinet advisory",
            cves=["CVE-F-OTHER"],
            ranges=[
                AffectedRange(
                    advisory_id="FG-UNRELATED",
                    product_id="fortigate-other",
                    versions=VersionRange(train="7.2", upper="7.2.8"),
                    status="affected",
                )
            ],
        ),
        Advisory(
            id="CISCO-RELEVANT",
            vendor_id="cisco",
            title="Relevant Cisco advisory",
            cves=["CVE-C-1"],
            ranges=[
                AffectedRange(
                    advisory_id="CISCO-RELEVANT",
                    product_id="cisco-iosxe",
                    versions=VersionRange(train="17.9", upper="17.9.5"),
                    status="affected",
                )
            ],
        ),
    ):
        save_canonical_record(session, advisory)
    for enrichment in (
        Enrichment(cve_id="CVE-F-1", kev=True),
        Enrichment(cve_id="CVE-C-1", epss=0.8),
        Enrichment(cve_id="CVE-F-OTHER", kev=True),
    ):
        save_canonical_record(session, enrichment)
    for eol in (
        EoLRecord(id="eol-fortigate", vendor_id="fortinet", product_id="fortigate"),
        EoLRecord(id="eol-other", vendor_id="fortinet", product_id="fortigate-other"),
    ):
        save_canonical_record(session, eol)
    upsert_source_sync_state(session, "failed-feed", status="failed")
    upsert_source_sync_state(session, "healthy-feed", status="success")
    session.commit()
    session.expunge_all()


def test_matching_dataset_queries_only_selected_ranges_and_related_facts() -> None:
    session = make_session()
    seed(session)
    classes = (AdvisoryRow, AffectedRangeRow, EnrichmentRow, EoLRecordRow)
    loaded: dict[type[Any], list[str]] = {item: [] for item in classes}

    def capture(_session: Session, instance: Any) -> None:
        identity = getattr(instance, "id", getattr(instance, "cve_id", None))
        if type(instance) in loaded and identity is not None:
            loaded[type(instance)].append(identity)

    event.listen(Session, "loaded_as_persistent", capture)
    try:
        dataset = load_matching_dataset(
            session,
            MatchRequest(
                assets=[
                    Asset(
                        asset_ref="fortigate-1",
                        vendor="fortinet",
                        product="fortigate",
                        version="7.2.5",
                    ),
                    Asset(
                        asset_ref="iosxe-1",
                        vendor="cisco",
                        product="cisco-iosxe",
                        version="17.9.4a",
                    ),
                    Asset(
                        asset_ref="unresolved",
                        vendor="missing-vendor",
                        version="1.0.0",
                    ),
                ]
            ),
        )
    finally:
        event.remove(Session, "loaded_as_persistent", capture)

    assert {advisory.id for advisory in dataset.advisories} == {"FG-RELEVANT", "CISCO-RELEVANT"}
    assert {enrichment.cve_id for enrichment in dataset.enrichments} == {"CVE-F-1", "CVE-C-1"}
    assert {record.id for record in dataset.eol} == {"eol-fortigate"}
    assert dataset.unavailable_sources == ["failed-feed"]
    assert set(loaded[AdvisoryRow]) == {"FG-RELEVANT", "CISCO-RELEVANT"}
    assert set(loaded[AffectedRangeRow]) == {1, 3}
    assert set(loaded[EnrichmentRow]) == {"CVE-F-1", "CVE-C-1"}
    assert set(loaded[EoLRecordRow]) == {"eol-fortigate"}


def test_db_matching_preserves_unresolved_assets_and_source_status() -> None:
    session = make_session()
    seed(session)
    response = match_request(
        session,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="known",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                ),
                Asset(asset_ref="unknown", vendor="missing-vendor", version="1.0.0"),
                Asset(asset_ref="ambiguous", vendor="fortinet", version="7.2.5"),
            ]
        ),
    )
    assert response.results[0].status == "resolved"
    assert response.results[0].findings[0].advisory_id == "FG-RELEVANT"
    assert response.results[0].findings[0].verdict == "unknown"
    assert response.results[1].status == "unresolved"
    assert response.results[1].findings[0].advisory_id is None
    assert response.results[2].status == "unresolved"
    assert response.results[2].findings[0].advisory_id is None


def test_db_resolve_reads_catalog_without_loading_advisories() -> None:
    session = make_session()
    seed(session)
    loaded: list[str] = []

    def capture(_session: Session, instance: Any) -> None:
        if isinstance(instance, (AdvisoryRow, AffectedRangeRow, EnrichmentRow, EoLRecordRow)):
            loaded.append(type(instance).__name__)

    event.listen(Session, "loaded_as_persistent", capture)
    try:
        response = resolve_request(
            session,
            ResolveRequest(raw_strings=["Fortinet FortiOS Software, Version 7.2.5"]),
        )
    finally:
        event.remove(Session, "loaded_as_persistent", capture)

    assert response.results[0].status == "resolved"
    assert response.results[0].product_id == "fortigate"
    assert loaded == []


def test_db_source_scope_keeps_unrelated_failure_from_blocking_positive_match() -> None:
    session = make_session()
    seed(session)
    upsert_source_sync_state(
        session,
        "failed-feed",
        status="failed",
        metadata={"kind": "advisory", "vendor_scope": ["arista"]},
    )
    session.commit()
    response = match_request(
        session,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="known",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "affected"


def test_db_relevant_failure_blocks_but_operator_exclusion_does_not() -> None:
    session = make_session()
    seed(session)
    upsert_source_sync_state(
        session,
        "failed-feed",
        status="failed",
        metadata={"kind": "advisory", "vendor_scope": ["fortinet"]},
    )
    session.commit()
    blocked = match_request(
        session,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="blocked",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert blocked.results[0].findings[0].verdict == "unknown"

    upsert_source_sync_state(
        session,
        "failed-feed",
        status="disabled",
        metadata={
            "kind": "advisory",
            "vendor_scope": ["fortinet"],
            "allowed": False,
            "operator_excluded": True,
        },
    )
    session.commit()
    allowed = match_request(
        session,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="allowed",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert allowed.results[0].findings[0].verdict == "affected"
