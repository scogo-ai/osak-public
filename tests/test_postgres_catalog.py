from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from osak.connectors.base import RawDocument
from osak.connectors.cvelistv5 import CveListV5Connector
from osak.core.models import Product
from osak.core.repository import get_advisory, get_product, get_vendor
from osak.ingest.core_adapter import CoreIngestRepository
from osak.ingest.merge import SourceContext

DATABASE_URL = os.environ.get("OSAK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None,
    reason="set OSAK_TEST_DATABASE_URL to run PostgreSQL catalog tests",
)


def _payload(identifier: str, *, vendor: str, product: str) -> bytes:
    return json.dumps(
        {
            "cveMetadata": {"cveId": identifier, "assignerShortName": "MITRE"},
            "containers": {
                "cna": {
                    "providerMetadata": {"shortName": "MITRE"},
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


def test_postgres_keeps_mitre_advisories_and_identified_products() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    connector = CveListV5Connector()
    rows = (
        ("CVE-2026-99001", "n/a", "n/a"),
        ("CVE-2026-99002", "Cisco", "Cisco IOS XE Software"),
    )
    with Session(engine, expire_on_commit=False) as session:
        for identifier, vendor, product in rows:
            raw = RawDocument(
                url=f"https://example.invalid/{identifier}.json",
                fetched_at=datetime.now(UTC),
                content=_payload(identifier, vendor=vendor, product=product),
            )
            with session.begin():
                repository = CoreIngestRepository(session)
                for record in connector.normalize(raw):
                    provenance = record.provenance[0]
                    repository.merge_record(
                        record,
                        SourceContext(
                            source="cvelistv5",
                            fetched_at=provenance.fetched_at,
                            url=provenance.url,
                            license="CVE",
                        ),
                    )

        placeholder = get_advisory(session, "CVE-2026-99001")
        identified = get_advisory(session, "CVE-2026-99002")
        assert placeholder is not None
        assert identified is not None
        assert get_vendor(session, "mitre") is not None
        assert get_vendor(session, "cisco") is not None
        assert get_product(session, "cisco-iosxe") is not None
        assert get_product(session, "mitre-n-a") is None
        assert placeholder.ranges == []
        assert identified.ranges
    engine.dispose()


def test_postgres_roundtrips_bounded_id_with_long_identified_display_label() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    connector = CveListV5Connector()
    long_product = "Cisco " + ("Release Family " * 80)
    raw = RawDocument(
        url="https://example.invalid/CVE-2026-99003.json",
        fetched_at=datetime.now(UTC),
        content=_payload("CVE-2026-99003", vendor="Cisco", product=long_product),
    )
    records = list(connector.normalize(raw))
    product = next(record for record in records if isinstance(record, Product))
    assert len(product.id) <= 256
    with Session(engine, expire_on_commit=False) as session:
        with session.begin():
            repository = CoreIngestRepository(session)
            for record in records:
                provenance = record.provenance[0]
                repository.merge_record(
                    record,
                    SourceContext(
                        source="cvelistv5",
                        fetched_at=provenance.fetched_at,
                        url=provenance.url,
                        license="CVE",
                    ),
                )
        persisted = get_product(session, product.id)
        assert persisted is not None
        assert persisted.family == long_product
        assert persisted.os == long_product
    engine.dispose()

