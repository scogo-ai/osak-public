from __future__ import annotations

import os
from datetime import UTC, datetime
from threading import Barrier, Thread
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from osak.core.db_models import EnrichmentRow
from osak.core.models import (
    Advisory,
    AffectedRange,
    ClosedScopeEvidence,
    Enrichment,
    Product,
    Provenance,
    VersionRange,
)
from osak.core.repository import get_advisory, get_product
from osak.ingest.core_adapter import CoreIngestRepository
from osak.ingest.merge import Merger, SourceContext

DATABASE_URL = os.environ.get("OSAK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None,
    reason="set OSAK_TEST_DATABASE_URL to run PostgreSQL concurrency tests",
)


def _provenance(source: str) -> Provenance:
    return Provenance(
        source=source,
        fetched_at=datetime.now(UTC),
        url=f"https://example.invalid/{source}",
        license="fixture",
    )


def test_concurrent_first_enrichment_insert_is_serialized() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    cve_id = f"CVE-2026-CONCURRENT-{uuid4().hex}"
    barrier = Barrier(2)
    errors: list[BaseException] = []

    def write(source: str, score: float) -> None:
        try:
            with Session(engine, expire_on_commit=False) as session, session.begin():
                barrier.wait(timeout=10)
                repository = CoreIngestRepository(
                    session,
                    merger=Merger(source_precedence={"source-a": 100, "source-b": 90}),
                )
                record = Enrichment(
                    cve_id=cve_id,
                    epss=score,
                    provenance=[_provenance(source)],
                )
                repository.merge_record(record, SourceContext.from_record(record))
        except Exception as exc:  # noqa: BLE001 - collect thread failures for assertion
            errors.append(exc)

    first = Thread(target=write, args=("source-a", 0.9))
    second = Thread(target=write, args=("source-b", 0.1))
    first.start()
    second.start()
    first.join(timeout=15)
    second.join(timeout=15)
    assert not errors
    with Session(engine) as session:
        row = session.get(EnrichmentRow, cve_id)
        assert row is not None
        assert row.epss == 0.9
    engine.dispose()


def test_postgres_real_plugin_precedence_survives_stale_replay() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    advisory_id = f"cisco-sa-precedence-{uuid4().hex}"
    old_vendor = Advisory(
        id=advisory_id,
        vendor_id="cisco",
        title="Cisco publisher title",
        provenance=[_provenance("cisco_openvuln")],
    )
    fresh_nvd = old_vendor.model_copy(
        update={
            "title": "NVD replacement title",
            "provenance": [_provenance("nvd")],
        }
    )
    with Session(engine, expire_on_commit=False) as session:
        with session.begin():
            repository = CoreIngestRepository(session)
            repository.merge_record(old_vendor, SourceContext.from_record(old_vendor))
        with session.begin():
            repository = CoreIngestRepository(session)
            repository.merge_record(fresh_nvd, SourceContext.from_record(fresh_nvd))
        with session.begin():
            repository = CoreIngestRepository(session)
            repository.merge_record(fresh_nvd, SourceContext.from_record(fresh_nvd))
        stored = get_advisory(session, advisory_id)
        assert stored is not None
        assert stored.title == "Cisco publisher title"
        assert {item.source for item in stored.provenance if item.field == "title"} == {
            "cisco_openvuln"
        }
    engine.dispose()


def test_postgres_checker_query_slices_are_additive_and_correctable() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    advisory_id = f"cisco-sa-slices-{uuid4().hex}"

    def record(version: str, fixed: str, url: str) -> Advisory:
        return Advisory(
            id=advisory_id,
            vendor_id="cisco",
            title="Cisco checker",
            ranges=[
                AffectedRange(
                    advisory_id=advisory_id,
                    product_id="cisco-iosxe",
                    versions=VersionRange(exact=version, train=version.split(".")[0]),
                    status="affected",
                    fixed_versions=[fixed],
                    provenance=[
                        Provenance(
                            source="cisco_openvuln",
                            fetched_at=datetime.now(UTC),
                            url=url,
                            license="fixture",
                            field="ranges",
                        )
                    ],
                )
            ],
        )

    query_a = "https://checker.invalid/OSType/IOSXE?version=17.9.4&platformAlias=cat9k"
    query_b = "https://checker.invalid/OSType/IOSXE?version=17.3.5&platformAlias=cat9k"
    with Session(engine, expire_on_commit=False) as session:
        for item in (
            record("17.9.4", "17.9.5", query_a),
            record("17.3.5", "17.3.6", query_b),
            record("17.9.4", "17.9.6", query_a),
            record("17.9.4", "17.9.6", query_a),
        ):
            with session.begin():
                repository = CoreIngestRepository(session)
                repository.merge_record(item, SourceContext.from_record(item))
        stored = get_advisory(session, advisory_id)
        assert stored is not None
        assert len(stored.ranges) == 2
        assert {item.fixed_versions[0] for item in stored.ranges} == {"17.9.6", "17.3.6"}
    engine.dispose()


def test_postgres_authoritative_withdrawals_do_not_clear_unrelated_sources() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    advisory_id = f"cisco-sa-withdraw-{uuid4().hex}"
    source_url = f"https://example.invalid/csaf/{advisory_id}.json"
    scope = ClosedScopeEvidence(
        vendor_id="cisco",
        product_id="cisco-asa",
        hardware_models=["Cisco Firepower 1000 Series"],
        complete=True,
        explicit=True,
        provenance=[
            Provenance(
                source="cisco_csaf",
                fetched_at=datetime.now(UTC),
                url=source_url,
                license="fixture",
                field="closed_scope",
            )
        ],
    )
    first = Advisory(
        id=advisory_id,
        vendor_id="cisco",
        title="publisher",
        closed_scopes=[scope],
        provenance=[
            Provenance(
                source="cisco_csaf",
                fetched_at=datetime.now(UTC),
                url=source_url,
                license="fixture",
                field="advisory",
            )
        ],
    )
    unrelated = first.model_copy(
        update={
            "title": "unrelated source update",
            "closed_scopes": [],
            "provenance": [_provenance("nvd")],
        }
    )
    withdrawn = first.model_copy(update={"closed_scopes": []})
    product_id = f"cisco-asa-withdraw-{uuid4().hex}"
    product = Product(
        id=product_id,
        vendor_id="cisco",
        family="ASA",
        os="asa",
        scheme="cisco_asa",
        supported_platforms_by_release={"9.22(3)": ["Cisco Firepower 1000 Series"]},
        provenance=[
            Provenance(
                source="cisco_asa_compatibility",
                fetched_at=datetime.now(UTC),
                url="https://example.invalid/asa/matrix",
                license="fixture",
                field="supported_platforms_by_release",
            )
        ],
    )
    corrected_product = product.model_copy(update={"supported_platforms_by_release": {}})
    with Session(engine, expire_on_commit=False) as session:
        for item, context in (
            (first, SourceContext("cisco_csaf", datetime.now(UTC), source_url, "fixture")),
            (unrelated, SourceContext("nvd", datetime.now(UTC), "https://example.invalid/nvd", "fixture")),
            (withdrawn, SourceContext("cisco_csaf", datetime.now(UTC), source_url, "fixture")),
            (product, SourceContext("cisco_asa_compatibility", datetime.now(UTC), "https://example.invalid/asa/matrix", "fixture")),
            (corrected_product, SourceContext("cisco_asa_compatibility", datetime.now(UTC), "https://example.invalid/asa/matrix", "fixture")),
        ):
            with session.begin():
                CoreIngestRepository(session).merge_record(item, context)
        stored = get_advisory(session, advisory_id)
        assert stored is not None and stored.closed_scopes == []
        stored_product = get_product(session, product_id)
        assert stored_product is not None and stored_product.supported_platforms_by_release == {}
    engine.dispose()

