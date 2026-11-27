from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from osak.connectors.base import RawDocument, SourceLicense
from osak.core import repository as core
from osak.core.db import Base, SessionLocal, create_database_engine
from osak.core.db_models import ChangeRow, RawDocumentRow
from osak.core.models import (
    Advisory,
    AffectedRange,
    Enrichment,
    Product,
    Provenance,
    Vendor,
    VersionRange,
)
from osak.ingest.core_adapter import (
    CoreIngestRepository,
    CoreRawStore,
    CoreStreamingIngestRepository,
)
from osak.ingest.merge import Merger, SourceContext
from osak.ingest.worker import IngestWorker, RetryPolicy

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


class CoreFixtureConnector:
    id = "core-fixture"
    vendor_scope: ClassVar[list[str]] = ["fixture-vendor"]
    kind = "advisory"
    tier = "free"
    license = SourceLicense(
        name="fixture license",
        url="https://example.invalid/license",
        attribution="Synthetic fixture",
        redistribution="facts",
    )
    auth = "none"
    rate_limit = "1/s"
    schedule = 60

    def __init__(self, *, fail_normalize: bool = False) -> None:
        self.fail_normalize = fail_normalize

    def fetch(self, since: datetime | None):  # type: ignore[no-untyped-def]
        yield RawDocument(
            url="https://example.invalid/fixture.json",
            fetched_at=NOW,
            content=b'{"id":"core-1"}',
        )

    def normalize(self, raw: RawDocument):  # type: ignore[no-untyped-def]
        if self.fail_normalize:
            raise ValueError("synthetic normalization failure")
        return [
            Advisory(
                id="core-1",
                vendor_id="fixture-vendor",
                title="Core fixture",
                provenance=[
                    Provenance(
                        source=self.id,
                        fetched_at=raw.fetched_at,
                        url=raw.url,
                        license=self.license.name,
                    )
                ],
            )
        ]

    def healthcheck(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError


def make_session():  # type: ignore[no-untyped-def]
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return SessionLocal(bind=engine)


def make_streaming_repository():  # type: ignore[no-untyped-def]
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def scope():  # type: ignore[no-untyped-def]
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return engine, CoreStreamingIngestRepository(scope)


def test_worker_persists_raw_canonical_and_sync_state_in_core() -> None:
    session = make_session()
    try:
        repository = CoreIngestRepository(session)
        connector = CoreFixtureConnector()
        worker = IngestWorker(
            {connector.id: connector},
            repository,
            retry=RetryPolicy(max_attempts=1),
            clock=lambda: NOW,
            sleeper=lambda _: None,
        )

        result = worker.poll(connector.id)
        session.commit()

        assert result.success
        assert core.get_advisory(session, "core-1") is not None
        raw_rows = list(session.scalars(select(RawDocumentRow)))
        assert len(raw_rows) == 1
        state = core.get_source_sync_state(session, connector.id)
        assert state is not None
        assert state.status == "success"
        assert state.last_success_at == NOW
    finally:
        session.close()


def test_core_adapter_keeps_conflict_winner_and_loser() -> None:
    session = make_session()
    try:
        repository = CoreIngestRepository(
            session,
            merger=Merger(source_precedence={"nvd": 70, "vendor-psirt": 100}),
        )
        low = Advisory(
            id="conflict-1",
            vendor_id="fixture-vendor",
            title="NVD",
            provenance=[
                Provenance(
                    source="nvd",
                    fetched_at=NOW,
                    url="https://example.invalid/nvd",
                    license="NVD",
                )
            ],
        )
        high = low.model_copy(
            update={
                "title": "Vendor",
                "provenance": [
                    Provenance(
                        source="vendor-psirt",
                        fetched_at=NOW + timedelta(minutes=1),
                        url="https://example.invalid/vendor",
                        license="Vendor",
                    )
                ],
            }
        )
        repository.merge_record(low, SourceContext.from_record(low))
        result = repository.merge_record(high, SourceContext.from_record(high))
        repository.append_conflicts(result.conflicts)
        session.commit()

        assert core.get_advisory(session, "conflict-1").title == "Vendor"
        conflicts = core.list_conflicts(session, record_id="conflict-1")
        title_conflicts = [item for item in conflicts if item.field == "title"]
        assert title_conflicts
        assert title_conflicts[0].winner_source == "vendor-psirt"
        assert title_conflicts[0].loser_source == "nvd"
    finally:
        session.close()


def test_core_adapter_does_not_use_cve_fallback_for_advisory_identity() -> None:
    session = make_session()
    try:
        repository = CoreIngestRepository(session)
        cve = "CVE-2026-SHARED-ADVISORY"
        first = Advisory(
            id="cisco-sa-shared",
            vendor_id="cisco",
            title="Cisco advisory",
            cves=[cve],
            provenance=[
                Provenance(
                    source="cisco_openvuln",
                    fetched_at=NOW,
                    url="https://example.invalid/cisco",
                    license="Cisco",
                )
            ],
        )
        second = Advisory(
            id=cve,
            vendor_id="cve-backbone",
            title="CVE backbone record",
            cves=[cve],
            provenance=[
                Provenance(
                    source="cvelistv5",
                    fetched_at=NOW,
                    url="https://example.invalid/cve",
                    license="CVE",
                )
            ],
        )
        repository.merge_record(first, SourceContext.from_record(first))
        repository.merge_record(second, SourceContext.from_record(second))
        session.commit()

        assert core.get_advisory(session, "cisco-sa-shared").title == "Cisco advisory"
        assert core.get_advisory(session, cve).title == "CVE backbone record"
    finally:
        session.close()


def test_core_adapter_persists_checker_slices_and_replays_idempotently() -> None:
    session = make_session()
    try:
        repository = CoreIngestRepository(session)

        def advisory(version: str, fixed: str, url: str) -> Advisory:
            return Advisory(
                id="cisco-sa-slices",
                vendor_id="cisco",
                title="checker",
                ranges=[
                    AffectedRange(
                        advisory_id="cisco-sa-slices",
                        product_id="cisco-iosxe",
                        versions=VersionRange(exact=version, train=version.split(".")[0]),
                        status="affected",
                        fixed_versions=[fixed],
                        provenance=[
                            Provenance(
                                source="cisco_openvuln",
                                fetched_at=NOW,
                                url=url,
                                license="Cisco",
                                field="ranges",
                            )
                        ],
                    )
                ],
            )

        query_a = "https://checker.invalid/OSType/IOSXE?version=17.9.4&platformAlias=cat9k"
        query_b = "https://checker.invalid/OSType/IOSXE?version=17.3.5&platformAlias=cat9k"
        first = advisory("17.9.4", "17.9.5", query_a)
        second = advisory("17.3.5", "17.3.6", query_b)
        correction = advisory("17.9.4", "17.9.6", query_a)
        for item in (first, second, correction, correction):
            repository.merge_record(item, SourceContext.from_record(item))
        session.commit()

        stored = core.get_advisory(session, "cisco-sa-slices")
        assert stored is not None
        assert len(stored.ranges) == 2
        assert {item.fixed_versions[0] for item in stored.ranges} == {"17.9.6", "17.3.6"}
    finally:
        session.close()


def test_core_adapter_skips_canonical_save_after_unchanged_replay(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = make_session()
    try:
        repository = CoreIngestRepository(session)
        record = Vendor(
            id="replay-vendor",
            name="Replay vendor",
            provenance=[
                Provenance(
                    source="core-fixture",
                    fetched_at=NOW,
                    url="https://example.invalid/replay",
                    license="fixture",
                )
            ],
        )
        context = SourceContext.from_record(record)
        repository.merge_record(record, context)
        repository.merge_record(record, context)

        calls: list[object] = []
        monkeypatch.setattr(
            core, "save_canonical_record", lambda *args, **kwargs: calls.append(args)
        )
        result = repository.merge_record(record, context)

        assert result.changed is False
        assert calls == []
    finally:
        session.close()


def test_core_raw_store_supports_replay_reads() -> None:
    session = make_session()
    try:
        store = CoreRawStore(session)
        raw = RawDocument(
            url="https://example.invalid/raw",
            fetched_at=NOW,
            content=b"raw",
        )
        blob = store.put("core-fixture", raw)
        session.commit()

        assert store.get(blob.content_hash).content == b"raw"
        assert list(store.iter_hashes()) == [blob.content_hash]
    finally:
        session.close()


def test_repeated_enrichment_save_does_not_emit_change_spam() -> None:
    session = make_session()
    try:
        enrichment = Enrichment(cve_id="CVE-2026-ENRICHMENT", epss=0.42)
        core.save_canonical_record(session, enrichment, source_id="epss")
        session.commit()
        first_count = session.query(ChangeRow).count()

        core.save_canonical_record(session, enrichment, source_id="epss")
        session.commit()

        assert session.query(ChangeRow).count() == first_count
    finally:
        session.close()


def test_core_raw_document_survives_normalization_failure() -> None:
    session = make_session()
    try:
        repository = CoreIngestRepository(session)
        connector = CoreFixtureConnector(fail_normalize=True)
        worker = IngestWorker(
            {connector.id: connector},
            repository,
            retry=RetryPolicy(max_attempts=1),
            clock=lambda: NOW,
            sleeper=lambda _: None,
        )

        result = worker.poll(connector.id)
        session.commit()

        assert not result.success
        assert repository.get_checkpoint(connector.id) is None
        assert list(session.scalars(select(RawDocumentRow)))
        assert core.get_source_sync_state(session, connector.id).status == "failed"
    finally:
        session.close()


def test_streaming_repository_retries_mid_poll_after_committing_raw() -> None:
    class MidPollConnector(CoreFixtureConnector):
        def __init__(self) -> None:
            super().__init__()
            self.fetch_calls = 0

        def fetch(self, since):  # type: ignore[no-untyped-def]
            del since
            with SessionLocal(bind=engine) as observer:
                state = core.get_source_sync_state(observer, self.id)
                assert state is not None and state.status == "running"
                assert state.last_started_at == NOW
                assert state.last_success_at is None
            assert repository.source_status_at(self.id, NOW).state == "never_synced"
            self.fetch_calls += 1
            yield RawDocument(
                url="https://example.invalid/one",
                fetched_at=NOW,
                content=b"one",
            )
            if self.fetch_calls == 1:
                raise TimeoutError("mid-poll")
            yield RawDocument(
                url="https://example.invalid/two",
                fetched_at=NOW + timedelta(seconds=1),
                content=b"two",
            )

    engine, repository = make_streaming_repository()
    connector = MidPollConnector()
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=2, initial_delay=0),
        clock=iter([NOW, NOW + timedelta(hours=1)]).__next__,
        sleeper=lambda _: None,
    )

    result = worker.poll(connector.id)

    assert result.success
    assert connector.fetch_calls == 2
    checkpoint = repository.get_checkpoint(connector.id)
    assert checkpoint is not None
    assert checkpoint.last_success_at == NOW + timedelta(hours=1)
    assert checkpoint.cursor == NOW + timedelta(seconds=1)
    with SessionLocal(bind=engine) as session:
        assert session.query(RawDocumentRow).count() == 2



def test_advisory_cve_scope_uses_affected_product_vendor() -> None:
    with make_session() as session:
        core.save_canonical_record(
            session,
            Product(id="cisco-iosxe", vendor_id="cisco", family="IOS XE", os="IOS XE", scheme="cisco_iosxe"),
        )
        core.save_canonical_record(session, Advisory(
            id="CVE-2024-20338",
            vendor_id="certcc",
            title="Cross-vendor fixture",
            cves=["CVE-2024-20338"],
            ranges=[AffectedRange(
                advisory_id="CVE-2024-20338", product_id="cisco-iosxe",
                versions=VersionRange(exact="17.9.4"), status="affected",
            )],
        ))
        repository = CoreIngestRepository(session)
        assert repository.advisory_cve_ids(["cisco"]) == {"CVE-2024-20338"}
        assert repository.advisory_cve_ids(["fortinet"]) == set()
