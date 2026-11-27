"""Regression tests that require a PostgreSQL 16 database.

Run with ``OSAK_TEST_DATABASE_URL`` pointing at an isolated database that has
already been upgraded with Alembic.  The suite skips in normal local runs so
the SQLite unit tests remain fast and dependency-free.
"""

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from osak.connectors.base import RawDocument
from osak.core.db_models import (
    AdvisoryCVERow,
    AffectedRangeRow,
    ProvenanceRow,
    RawDocumentRow,
    RawObservationRow,
)
from osak.core.models import (
    Advisory,
    AffectedRange,
    Enrichment,
    Product,
    Provenance,
    Vendor,
    VersionRange,
)
from osak.core.repository import (
    count_advisories,
    get_advisory,
    list_advisories,
    list_raw_observations,
    load_matching_dataset,
    save_canonical_record,
    store_raw_document,
)

DATABASE_URL = os.environ.get("OSAK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="set OSAK_TEST_DATABASE_URL to run PostgreSQL integration tests"
)


@pytest.fixture(scope="module")
def pg_engine():
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.connect() as connection:
        connection.exec_driver_sql("select current_setting('server_version_num')")
    yield engine
    engine.dispose()


@pytest.fixture
def pg_session(pg_engine):
    with Session(pg_engine, expire_on_commit=False) as session:
        yield session


def _id(prefix: str) -> str:
    return f"pg-test-{prefix}-{uuid4().hex[:10]}"


def _provenance(source: str, field: str = "*") -> Provenance:
    return Provenance(
        source=source,
        field=field,
        fetched_at=datetime(2026, 11, 27, 12, 0, tzinfo=UTC),
        url="https://example.test/pg-fixture",
        license="test-facts",
    )


def _seed_vendor_product(session: Session, prefix: str) -> tuple[Vendor, Product]:
    vendor = Vendor(id=_id(f"vendor-{prefix}"), name=f"PG Test Vendor {prefix}")
    product = Product(
        id=_id(f"product-{prefix}"),
        vendor_id=vendor.id,
        family=f"PG Test Product {prefix}",
        os="test-os",
        scheme="test-scheme",
    )
    save_canonical_record(session, vendor)
    save_canonical_record(session, product)
    return vendor, product


def test_postgres_upsert_replaces_ranges_and_cve_links(pg_session: Session) -> None:
    vendor, product = _seed_vendor_product(pg_session, "update")
    advisory_id = _id("advisory-update")
    old_cve = _id("cve-old")
    retained_cve = _id("cve-retained")
    new_cve = _id("cve-new")

    first = Advisory(
        id=advisory_id,
        vendor_id=vendor.id,
        title="PG test first revision",
        cves=[old_cve, retained_cve],
        ranges=[
            AffectedRange(
                advisory_id=advisory_id,
                product_id=product.id,
                versions=VersionRange(train="1", upper="1.1"),
                status="affected",
                fixed_versions=["1.1"],
            ),
            AffectedRange(
                advisory_id=advisory_id,
                product_id=product.id,
                versions=VersionRange(train="2", upper="2.1"),
                status="fixed",
                fixed_versions=["2.1"],
            ),
        ],
        provenance=[_provenance("test-source-a", "title")],
    )
    save_canonical_record(pg_session, first)
    pg_session.commit()

    second = first.model_copy(
        update={
            "title": "PG test second revision",
            "cves": [retained_cve, new_cve],
            "ranges": [
                AffectedRange(
                    advisory_id=advisory_id,
                    product_id=product.id,
                    versions=VersionRange(train="2", upper="2.2"),
                    status="affected",
                    fixed_versions=["2.2"],
                )
            ],
            "provenance": [_provenance("test-source-b", "title")],
        }
    )
    save_canonical_record(pg_session, second)
    # A replay of the same normalized record must be idempotent on PostgreSQL.
    save_canonical_record(pg_session, second)
    pg_session.commit()

    ranges = list(
        pg_session.scalars(
            select(AffectedRangeRow).where(AffectedRangeRow.advisory_id == advisory_id)
        )
    )
    links = list(
        pg_session.scalars(select(AdvisoryCVERow).where(AdvisoryCVERow.advisory_id == advisory_id))
    )
    provenance = list(
        pg_session.scalars(
            select(ProvenanceRow).where(
                ProvenanceRow.record_type == "advisory",
                ProvenanceRow.record_id == advisory_id,
            )
        )
    )
    assert len(ranges) == 1
    assert ranges[0].versions["upper"] == "2.2"
    assert {link.cve_id for link in links} == {retained_cve, new_cve}
    assert len(links) == 2
    assert len(provenance) == 1
    assert provenance[0].source == "test-source-b"
    assert get_advisory(pg_session, old_cve) is None
    assert get_advisory(pg_session, new_cve).id == advisory_id


def test_postgres_raw_blob_keeps_cross_source_observations(pg_session: Session) -> None:
    content = b'{"record":"same-test-document"}'
    first = RawDocument(
        url="https://source-a.example.test/raw",
        fetched_at=datetime(2026, 11, 27, 12, 0, tzinfo=UTC),
        content=content,
        media_type="application/json",
    )
    second = RawDocument(
        url="https://source-b.example.test/raw",
        fetched_at=datetime(2026, 11, 27, 12, 1, tzinfo=UTC),
        content=content,
        media_type="application/json",
    )
    first_row = store_raw_document(pg_session, first, source_id="test-source-a")
    second_row = store_raw_document(pg_session, second, source_id="test-source-b")
    replay_row = store_raw_document(pg_session, first, source_id="test-source-a")
    pg_session.commit()

    assert first_row.content_hash == second_row.content_hash == replay_row.content_hash
    documents = list(
        pg_session.scalars(
            select(RawDocumentRow).where(RawDocumentRow.content_hash == first_row.content_hash)
        )
    )
    observations = list_raw_observations(pg_session, first_row.content_hash)
    assert len(documents) == 1
    assert len(observations) == 2
    assert {observation.source_id for observation in observations} == {
        "test-source-a",
        "test-source-b",
    }
    assert {observation.url for observation in observations} == {first.url, second.url}
    assert (
        pg_session.scalar(
            select(RawObservationRow.content_hash).where(
                RawObservationRow.content_hash == first_row.content_hash,
                RawObservationRow.source_id == "test-source-b",
            )
        )
        == first_row.content_hash
    )


def test_postgres_matching_subset_is_mixed_vendor_and_bounded(pg_session: Session) -> None:
    vendor_a, product_a = _seed_vendor_product(pg_session, "mixed-a")
    vendor_b, product_b = _seed_vendor_product(pg_session, "mixed-b")
    unrelated_vendor, unrelated_product = _seed_vendor_product(pg_session, "mixed-unrelated")

    def advisory(vendor: Vendor, product: Product, suffix: str) -> Advisory:
        advisory_id = _id(f"advisory-{suffix}")
        return Advisory(
            id=advisory_id,
            vendor_id=vendor.id,
            title=f"PG test {suffix}",
            cves=[_id(f"cve-{suffix}")],
            ranges=[
                AffectedRange(
                    advisory_id=advisory_id,
                    product_id=product.id,
                    versions=VersionRange(train="1", upper="1.1"),
                    status="affected",
                )
            ],
        )

    advisory_a = advisory(vendor_a, product_a, "mixed-a")
    advisory_b = advisory(vendor_b, product_b, "mixed-b")
    save_canonical_record(pg_session, advisory_a)
    save_canonical_record(pg_session, advisory_b)
    save_canonical_record(
        pg_session, advisory(unrelated_vendor, unrelated_product, "mixed-unrelated")
    )
    save_canonical_record(pg_session, Enrichment(cve_id=_id("enrichment-mixed"), kev=False))
    pg_session.commit()

    dataset = load_matching_dataset(
        pg_session,
        vendor_product_pairs=[(vendor_a.id, product_a.id), (vendor_b.id, product_b.id)],
    )
    assert {vendor.id for vendor in dataset.vendors} == {vendor_a.id, vendor_b.id}
    assert {product.id for product in dataset.products} == {product_a.id, product_b.id}
    assert {advisory.id for advisory in dataset.advisories} == {advisory_a.id, advisory_b.id}
    assert all(advisory.vendor_id in {vendor_a.id, vendor_b.id} for advisory in dataset.advisories)
    assert unrelated_vendor.id not in {vendor.id for vendor in dataset.vendors}
    assert count_advisories(pg_session, vendor_id=vendor_a.id) == 1
    assert len(list_advisories(pg_session, page=1, page_size=1, vendor_id=vendor_a.id)) == 1

    indexes = inspect(pg_session.bind).get_indexes("advisories")
    index_names = {index["name"] for index in indexes}
    assert {
        "ix_advisories_vendor_id",
        "ix_advisories_updated",
        "ix_advisories_severity",
    } <= index_names
