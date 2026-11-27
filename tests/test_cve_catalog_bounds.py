from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from osak.connectors.base import RawDocument
from osak.connectors.cvelistv5 import CveListV5Connector
from osak.core.db import Base, SessionLocal, create_database_engine
from osak.core.db_models import ProductRow, ProvenanceRow, VendorRow
from osak.core.models import Advisory, Product, Provenance, Vendor
from osak.ingest.core_adapter import CoreIngestRepository
from osak.ingest.merge import Merger, SourceContext
from osak.ingest.persistence import InMemoryRepository

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def _cve_payload(identifier: str, *, vendor: str = "Cisco", product: str = "Cisco IOS XE Software") -> bytes:
    return json.dumps(
        {
            "cveMetadata": {
            "cveId": identifier,
                "assignerShortName": vendor,
                "datePublished": "2026-11-27T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "providerMetadata": {"shortName": vendor},
                    "title": identifier,
                    "affected": [
                        {
                            "vendor": vendor,
                            "product": product,
                            "versions": [{"version": "17.9.4", "status": "affected"}],
                        }
                    ],
                }
            },
        }
    ).encode()


def _records(connector: CveListV5Connector, identifier: str, fetched_at: datetime):
    raw = RawDocument(
        url=f"https://example.invalid/{identifier}.json",
        fetched_at=fetched_at,
        content=_cve_payload(identifier),
    )
    return list(connector.normalize(raw))


def test_placeholder_cve_identity_is_filtered_without_dropping_advisory() -> None:
    connector = CveListV5Connector()
    raw = RawDocument(
        url="https://example.invalid/mitre.json",
        fetched_at=NOW,
        content=_cve_payload("CVE-2026-99999", vendor="MITRE", product="n/a"),
    )

    records = list(connector.normalize(raw))

    assert any(isinstance(record, Advisory) for record in records)
    assert any(isinstance(record, Vendor) and record.id == "mitre" for record in records)
    assert not any(isinstance(record, Vendor) and record.id == "n-a" for record in records)
    assert not any(
        isinstance(record, Product) and record.id in {"n-a-n-a", "mitre-n-a"}
        for record in records
    )
    advisory = next(record for record in records if isinstance(record, Advisory))
    assert advisory.ranges == []


def test_official_cve_2016_8216_shape_does_not_construct_placeholder_long_product() -> None:
    connector = CveListV5Connector()
    official_product = (
        "EMC Data Domain DD OS EMC Data Domain OS (DD OS) 5.4 all versions, "
        "EMC Data Domain OS (DD OS) 5.5 family all versions prior to 5.5.5.0, "
        "EMC Data Domain OS (DD OS) 5.6 family all versions prior to 5.6.2.0, "
        "EMC Data Domain OS (DD OS) 5.7 family all versions prior to 5.7.2.10"
    )
    raw = RawDocument(
        url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2016/8xxx/CVE-2016-8216.json",
        fetched_at=NOW,
        content=_cve_payload("CVE-2016-8216", vendor="n/a", product=official_product),
    )

    records = list(connector.normalize(raw))

    advisory = next(record for record in records if isinstance(record, Advisory))
    assert advisory.id == "CVE-2016-8216"
    assert advisory.ranges == []
    assert all(len(getattr(record, "id", "")) <= 256 for record in records)


def test_legitimate_long_product_identity_is_bounded_deterministically() -> None:
    connector = CveListV5Connector()
    long_name = "Cisco " + ("Release Family " * 80)
    first = list(
        connector.normalize(
            RawDocument(
                url="https://example.invalid/long-1.json",
                fetched_at=NOW,
                content=_cve_payload("CVE-2026-99101", vendor="Cisco", product=long_name),
            )
        )
    )
    second = list(
        connector.normalize(
            RawDocument(
                url="https://example.invalid/long-2.json",
                fetched_at=NOW,
                content=_cve_payload("CVE-2026-99102", vendor="Cisco", product=long_name),
            )
        )
    )
    first_product = next(record for record in first if isinstance(record, Product))
    second_product = next(record for record in second if isinstance(record, Product))
    assert len(first_product.id) <= 256
    assert first_product.id == second_product.id


def test_bulk_catalog_identity_provenance_stays_bounded() -> None:
    connector = CveListV5Connector()
    repository = InMemoryRepository(merger=Merger())
    for index in range(300):
        identifier = f"CVE-2026-{10000 + index}"
        for record in _records(connector, identifier, NOW + timedelta(seconds=index)):
            context = SourceContext(
                source="cvelistv5",
                fetched_at=record.provenance[0].fetched_at,
                url=record.provenance[0].url,
                license="CVE",
            )
            repository.merge_record(record, context)

    vendor = next(record for record in repository.iter_records() if isinstance(record, Vendor))
    product = next(record for record in repository.iter_records() if isinstance(record, Product))
    assert len(vendor.provenance) <= len(Vendor.model_fields)
    assert len(product.provenance) <= len(Product.model_fields)
    assert len(json.dumps(vendor.model_dump(mode="json"))) < 10_000
    assert len(json.dumps(product.model_dump(mode="json"))) < 10_000


def test_existing_sql_catalog_rows_are_not_rewritten_for_unchanged_identity() -> None:
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    connector = CveListV5Connector()
    with SessionLocal(bind=engine) as session:
        repository = CoreIngestRepository(session, merger=Merger())
        for index in range(120):
            for record in _records(connector, f"CVE-2026-{20000 + index}", NOW):
                context = SourceContext(
                    source="cvelistv5",
                    fetched_at=record.provenance[0].fetched_at,
                    url=record.provenance[0].url,
                    license="CVE",
                )
                repository.merge_record(record, context)
        session.commit()

        assert session.query(VendorRow).count() == 1
        assert session.query(ProductRow).count() == 1
        catalog_provenance = session.query(ProvenanceRow).filter(
            ProvenanceRow.record_type.in_(["vendor", "product"])
        )
        assert catalog_provenance.count() <= len(Vendor.model_fields) + len(Product.model_fields)


def test_catalog_additive_aliases_keep_independent_source_lineage() -> None:
    old = Product(
        id="cisco-iosxe",
        vendor_id="cisco",
        family="IOS XE",
        os="iosxe",
        scheme="cisco_iosxe",
        aliases=["Cisco IOS XE"],
        provenance=[
            Provenance(
                source="cisco_openvuln",
                fetched_at=NOW,
                url="https://example.invalid/cisco",
                license="Cisco",
                field="product",
            )
        ],
    )
    new = old.model_copy(
        update={
            "aliases": ["IOS-XE"],
            "provenance": [
                Provenance(
                    source="cvelistv5",
                    fetched_at=NOW,
                    url="https://example.invalid/cve",
                    license="CVE",
                    field="product",
                )
            ],
        }
    )
    merger = Merger()
    result = merger.merge(old, new, SourceContext("cvelistv5", NOW, "https://example.invalid/cve", "CVE"))

    assert set(result.record.aliases) == {"IOS-XE", "Cisco IOS XE"}
    alias_sources = {
        item.source for item in result.record.provenance if item.field == "aliases"
    }
    assert alias_sources == {"cisco_openvuln", "cvelistv5"}
