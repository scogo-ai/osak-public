from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from osak.connectors.base import RawDocument
from osak.connectors.nvd import NvdConnector
from osak.core.db import Base
from osak.core.models import Enrichment
from osak.core.repository import load_dataset, save_canonical_record

FIXTURES = Path(__file__).parents[1] / "fixtures" / "connectors"


def real_document() -> RawDocument:
    metadata = json.loads((FIXTURES / "nvd_real_page_0.meta.json").read_text())
    return RawDocument(
        url=metadata["source_url"],
        fetched_at=datetime.fromisoformat(metadata["retrieved_at"]),
        content=(FIXTURES / "nvd_real_page_0.json").read_bytes(),
        media_type="application/json",
    )


def test_real_nvd_projection_normalizes_cve_cvss_and_cpe() -> None:
    records = list(NvdConnector().normalize(real_document()))

    assert len(records) == 1
    enrichment = records[0]
    assert isinstance(enrichment, Enrichment)
    assert enrichment.cve_id == "CVE-1999-0095"
    assert enrichment.cvss == 10.0
    assert enrichment.cvss_version == "2.0"
    assert enrichment.cpes == ["cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*"]
    assert enrichment.provenance[0].url == real_document().url


def test_nvd_cpe_projection_excludes_nonvulnerable_and_negated_matches() -> None:
    configurations = [
        {
            "nodes": [
                {
                    "negate": False,
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:vendor:vulnerable:*:*:*:*:*:*:*:*", "vulnerable": True},
                        {"criteria": "cpe:2.3:a:vendor:excluded:*:*:*:*:*:*:*:*", "vulnerable": False},
                        {"criteria": "cpe:2.3:a:vendor:unspecified:*:*:*:*:*:*:*:*"},
                    ],
                },
                {
                    "negate": True,
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:vendor:negated:*:*:*:*:*:*:*:*", "vulnerable": True}
                    ],
                },
            ]
        }
    ]

    assert NvdConnector._cpes(configurations) == [
        "cpe:2.3:a:vendor:vulnerable:*:*:*:*:*:*:*:*"
    ]


def test_real_nvd_enrichment_round_trips_through_persistence() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    records = list(NvdConnector().normalize(real_document()))
    with Session(engine) as session:
        save_canonical_record(session, records[0])
        session.commit()
        dataset = load_dataset(session)

    assert dataset.enrichments[0].cve_id == "CVE-1999-0095"
    assert dataset.enrichments[0].cpes == [
        "cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*"
    ]
