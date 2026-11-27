from datetime import UTC, date, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from osak.connectors.base import RawDocument
from osak.core.db import Base
from osak.core.db_models import RawDocumentRow
from osak.core.models import (
    Advisory,
    AffectedRange,
    ClosedScopeEvidence,
    Condition,
    Enrichment,
    EoLRecord,
    Product,
    Provenance,
    Remediation,
    Vendor,
    VersionRange,
)
from osak.core.repository import (
    get_advisory,
    list_advisories,
    list_changes,
    list_conflicts,
    list_source_sync_states,
    load_dataset,
    record_change,
    record_conflict,
    save_canonical_record,
    store_raw_document,
    upsert_source_sync_state,
)


def make_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def provenance(source: str = "fixture") -> Provenance:
    return Provenance(
        source=source,
        fetched_at=datetime(2026, 11, 27, 12, 0, tzinfo=UTC),
        url="https://example.test/advisory",
        license="facts",
    )


def test_canonical_records_round_trip_as_dataset() -> None:
    session = make_session()
    vendor = Vendor(
        id="test-vendor",
        name="Test Vendor",
        aliases=["test-vendor-alias"],
        psirt_urls=["https://example.test/psirt"],
        cna="TEST-CNA",
        provenance=[provenance("test-source")],
    )
    product = Product(
        id="test-product",
        vendor_id="test-vendor",
        family="Test Product",
        os="Test OS",
        scheme="test-scheme",
        aliases=["test-product-alias"],
        supported_platforms_by_release={"1.2": ["model-a", "model-b"]},
        provenance=[
            provenance("compatibility").model_copy(
                update={"field": "supported_platforms_by_release"}
            ),
            provenance("test-source"),
        ],
    )
    advisory = Advisory(
        id="TEST-ADVISORY-001",
        vendor_id="test-vendor",
        title="Test advisory",
        published=datetime(2026, 11, 1, tzinfo=UTC),
        updated=datetime(2026, 11, 2, tzinfo=UTC),
        severity="high",
        cves=["TEST-CVE-0001"],
        ranges=[
            AffectedRange(
                advisory_id="TEST-ADVISORY-001",
                product_id="test-product",
                versions=VersionRange(train="1", upper="1.2"),
                status="affected",
                default_status="not_affected",
                fixed_versions=["1.2"],
                conditions=[Condition(feature="test-feature")],
                provenance=[provenance()],
            )
        ],
        closed_scopes=[
            ClosedScopeEvidence(
                vendor_id="test-vendor",
                product_id="test-product",
                hardware_models=["model-a", "model-b"],
                complete=True,
                explicit=True,
                provenance=[provenance("test-scope")],
            )
        ],
        remediation=Remediation(targets=["1.2"], workaround="Test workaround"),
        provenance=[provenance()],
    )
    enrichment = Enrichment(
        cve_id="TEST-CVE-0001",
        kev=True,
        kev_date=date(2026, 11, 3),
        epss=0.91,
        percentile=0.99,
        cvss=9.8,
        cvss_version="3.1",
        provenance=[provenance("test-kev")],
    )
    eol = EoLRecord(
        id="test-product-7.2",
        vendor_id="test-vendor",
        product_id="test-product",
        version="1",
        end_security=date(2028, 1, 1),
        provenance=[provenance("test-eol")],
    )

    for record in (vendor, product, advisory, enrichment, eol):
        save_canonical_record(session, record)
    session.commit()

    dataset = load_dataset(session)
    assert dataset.vendors == [vendor]
    assert dataset.products == [product]
    assert dataset.advisories == [advisory]
    assert dataset.advisories[0].closed_scopes == advisory.closed_scopes
    assert dataset.enrichments == [enrichment]
    assert dataset.eol == [eol]


def test_raw_documents_are_content_hashed_and_immutable() -> None:
    session = make_session()
    first = RawDocument(
        url="https://example.test/feed.json",
        fetched_at=datetime(2026, 11, 27, tzinfo=UTC),
        content=b'{"id":"one"}',
    )
    row = store_raw_document(session, first, source_id="fixture")
    session.commit()

    duplicate = store_raw_document(
        session,
        RawDocument(
            url="https://example.test/other-url",
            fetched_at=datetime(2026, 11, 28, tzinfo=UTC),
            content=first.content,
        ),
        source_id="other",
    )
    session.commit()

    assert duplicate.content_hash == row.content_hash
    persisted = session.scalar(
        select(RawDocumentRow).where(RawDocumentRow.content_hash == row.content_hash)
    )
    assert persisted is not None
    assert persisted.url == first.url
    assert persisted.source_id == "fixture"
    assert persisted.content == first.content

    persisted.url = "https://example.test/changed"
    try:
        session.commit()
    except ValueError as exc:
        assert str(exc) == "raw documents are immutable"
        session.rollback()
    else:
        raise AssertionError("raw document update unexpectedly committed")


def test_sync_state_conflict_and_change_records_are_queryable() -> None:
    session = make_session()
    upsert_source_sync_state(
        session,
        "test-source",
        status="failed",
        error="timeout",
        records_seen=12,
    )
    record_conflict(
        session,
        record_type="advisory",
        record_id="TEST-CVE-0001",
        field="severity",
        winner_source="test-source-a",
        loser_source="test-source-b",
        winning_value="high",
        losing_value="medium",
    )
    record_change(
        session,
        record_type="advisory",
        record_id="TEST-CVE-0001",
        operation="upsert",
        source_id="test-source-a",
        payload={"severity": "high"},
    )
    session.commit()

    states = list_source_sync_states(session)
    assert states[0].source_id == "test-source"
    assert states[0].status == "failed"
    assert states[0].error == "timeout"
    assert len(list_conflicts(session)) == 1
    changes = list_changes(session)
    assert len(changes) == 1
    assert changes[0].record_id == "TEST-CVE-0001"


def test_advisory_queries_filter_in_the_database() -> None:
    session = make_session()
    save_canonical_record(session, Vendor(id="test-vendor-2", name="Test Vendor 2"))
    save_canonical_record(
        session,
        Product(
            id="test-product-2",
            vendor_id="test-vendor-2",
            family="Test OS",
            os="Test OS",
            scheme="test-scheme",
        ),
    )
    for advisory_id, cve, severity in (
        ("TEST-ADVISORY-HIGH", "TEST-CVE-0002", "high"),
        ("TEST-ADVISORY-LOW", "TEST-CVE-0003", "low"),
    ):
        save_canonical_record(
            session,
            Advisory(
                id=advisory_id,
                vendor_id="test-vendor-2",
                title=advisory_id,
                severity=severity,
                cves=[cve],
                ranges=[
                    AffectedRange(
                        advisory_id=advisory_id,
                        product_id="test-product-2",
                        versions=VersionRange(train="17.9", upper="17.9.5"),
                        status="affected",
                    )
                ],
            ),
        )
    save_canonical_record(session, Enrichment(cve_id="TEST-CVE-0002", kev=True))
    session.commit()

    rows = list_advisories(
        session, vendor_id="test-vendor-2", product_id="test-product-2", severity="high"
    )
    assert [row.id for row in rows] == ["TEST-ADVISORY-HIGH"]
    assert get_advisory(session, "TEST-CVE-0003").id == "TEST-ADVISORY-LOW"
    rows = list_advisories(session, cve_id="TEST-CVE-0002", kev=True)
    assert [row.id for row in rows] == ["TEST-ADVISORY-HIGH"]
