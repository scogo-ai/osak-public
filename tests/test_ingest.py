from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import httpx
import pytest

from osak.connectors.base import RawDocument, SourceLicense
from osak.connectors.first_epss import FirstEpssConnector
from osak.core.models import (
    Advisory,
    AffectedRange,
    ClosedScopeEvidence,
    Enrichment,
    Product,
    Provenance,
    VersionRange,
)
from osak.ingest.export import DatasetExporter, NightlyExportScheduler, read_jsonl_dataset
from osak.ingest.merge import DEFAULT_SOURCE_PRECEDENCE, Merger, SourceContext
from osak.ingest.persistence import InMemoryRepository
from osak.ingest.policy import PublicationPolicy
from osak.ingest.raw import FileRawStore
from osak.ingest.replay import RawReplayer
from osak.ingest.rollup import UsageMetadata, roll_up_metadata, roll_up_store
from osak.ingest.types import Checkpoint, SourceStatus
from osak.ingest.worker import IngestWorker, RetryPolicy, write_heartbeat

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def checker_range_for_test(
    version: str, status: str, source: str, url: str
) -> AffectedRange:
    return AffectedRange(
        advisory_id="cisco-sa-range-conflict",
        product_id="cisco-iosxe",
        versions=VersionRange(exact=version, train=version.split(".")[0]),
        status=status,  # type: ignore[arg-type]
        fixed_versions=[],
        provenance=[
            Provenance(
                source=source,
                fetched_at=NOW,
                url=url,
                license="fixture",
                field="ranges",
            )
        ],
    )


def license_for(redistribution: str) -> SourceLicense:
    return SourceLicense(
        name="fixture license",
        url="https://example.invalid/license",
        attribution="Fixture attribution",
        redistribution=redistribution,  # type: ignore[arg-type]
    )


class FixtureConnector:
    id = "fixture"
    vendor_scope: ClassVar[list[str]] = ["fixture-vendor"]
    kind = "advisory"
    tier = "free"
    license = license_for("facts")
    auth = "none"
    rate_limit = "1/s"
    schedule = 60

    def __init__(self, documents: list[RawDocument]) -> None:
        self.documents = documents
        self.calls = 0

    def fetch(self, since: datetime | None):  # type: ignore[no-untyped-def]
        self.calls += 1
        yield from self.documents

    def normalize(self, raw: RawDocument):  # type: ignore[no-untyped-def]
        return [
            Advisory(
                id="fixture-1",
                vendor_id="fixture-vendor",
                title="Synthetic advisory",
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


def raw_document(at: datetime = NOW) -> RawDocument:
    return RawDocument(
        url="https://example.invalid/fixture.json",
        fetched_at=at,
        content=b'{"fixture":true}',
    )


def test_cisco_lifecycle_is_optional_even_if_its_license_has_been_reviewed() -> None:
    from osak.connectors.cisco import CiscoEoxConnector

    connector = CiscoEoxConnector()
    reviewed = frozenset({connector.id})
    assert PublicationPolicy(reviewed_source_ids=reviewed).evaluate(connector).state == "disabled"
    selected = PublicationPolicy(enabled_source_ids=reviewed, reviewed_source_ids=reviewed)
    assert selected.evaluate(connector).allowed


def test_publication_policy_blocks_paid_and_unreviewed_sources() -> None:
    facts = FixtureConnector([])
    paid = FixtureConnector([])
    paid.id = "paid"
    paid.tier = "paid"
    restricted = FixtureConnector([])
    restricted.id = "restricted"
    restricted.license = license_for("restricted")

    policy = PublicationPolicy(public=True)

    assert policy.evaluate(facts).allowed
    assert not policy.evaluate(paid).allowed
    assert "paid" in policy.evaluate(paid).reason
    assert not policy.evaluate(restricted).allowed
    assert policy.evaluate(restricted).state == "unapproved"

    reviewed = PublicationPolicy(public=True, reviewed_source_ids={"restricted"})
    assert reviewed.evaluate(restricted).allowed


def test_merger_uses_field_precedence_and_logs_conflict() -> None:
    merger = Merger(
        source_precedence={"vendor-psirt": 100, "nvd": 70},
        default_precedence=0,
    )
    low = Advisory(
        id="CVE-2026-0001",
        vendor_id="vendor",
        title="NVD title",
        severity="low",
        provenance=[
            Provenance(
                source="nvd",
                fetched_at=NOW,
                url="https://example.invalid/nvd",
                license="NVD",
                field="*",
            )
        ],
    )
    high = Advisory(
        id="CVE-2026-0001",
        vendor_id="vendor",
        title="Vendor title",
        severity="high",
        provenance=[
            Provenance(
                source="vendor-psirt",
                fetched_at=NOW + timedelta(minutes=1),
                url="https://example.invalid/vendor",
                license="Vendor",
                field="*",
            )
        ],
    )

    first = merger.merge(None, low, SourceContext.from_record(low))
    second = merger.merge(first.record, high, SourceContext.from_record(high))

    assert second.record.title == "Vendor title"
    assert second.record.severity == "high"
    assert any(c.field == "title" and c.kept_source == "vendor-psirt" for c in second.conflicts)
    assert any(p.source == "vendor-psirt" for p in second.record.provenance)


def test_real_plugin_ids_keep_vendor_precedence_over_stale_nvd_in_any_order() -> None:
    stale_vendor = Advisory(
        id="cisco-sa-2026-0001",
        vendor_id="cisco",
        title="Vendor title",
        provenance=[
            Provenance(
                source="cisco_openvuln",
                fetched_at=NOW - timedelta(days=7),
                url="https://example.invalid/vendor",
                license="Cisco",
            )
        ],
    )
    fresh_nvd = Advisory(
        id=stale_vendor.id,
        vendor_id="cisco",
        title="NVD title",
        provenance=[
            Provenance(
                source="nvd",
                fetched_at=NOW,
                url="https://example.invalid/nvd",
                license="NVD",
            )
        ],
    )

    for records in ((stale_vendor, fresh_nvd), (fresh_nvd, stale_vendor)):
        merger = Merger()
        result = merger.merge(None, records[0], SourceContext.from_record(records[0]))
        result = merger.merge(result.record, records[1], SourceContext.from_record(records[1]))
        replay = merger.merge(result.record, records[1], SourceContext.from_record(records[1]))

        assert replay.record.title == "Vendor title"
        title_sources = {item.source for item in replay.record.provenance if item.field == "title"}
        assert title_sources == {"cisco_openvuln"}


def test_all_registered_source_ids_have_expected_precedence() -> None:
    expected = {
        "cvelistv5": 90,
        "cisco_csaf": 100,
        "cisco_openvuln": 100,
        "cisco_eox": 100,
        "arista_csaf": 100,
        "fortinet_psirt_rss": 100,
        "fortinet_psirt_page": 100,
        "fortinet_cna": 90,
        "nvd": 70,
        "cisa_kev": 50,
        "first_epss": 50,
        "endoflife_date_fortios": 50,
    }
    assert {source: DEFAULT_SOURCE_PRECEDENCE[source] for source in expected} == expected


def test_registered_plugin_ids_choose_field_winner_independent_of_order() -> None:
    plugin_ids = [
        "cvelistv5",
        "cisco_csaf",
        "cisco_openvuln",
        "cisco_eox",
        "arista_csaf",
        "fortinet_psirt_rss",
        "fortinet_psirt_page",
        "fortinet_cna",
        "cisa_kev",
        "first_epss",
        "endoflife_date_fortios",
    ]
    for plugin_id in plugin_ids:
        plugin = Advisory(
            id=f"advisory-{plugin_id}",
            vendor_id="vendor",
            title=f"{plugin_id} title",
            provenance=[
                Provenance(
                    source=plugin_id,
                    fetched_at=NOW - timedelta(days=30),
                    url=f"https://example.invalid/{plugin_id}",
                    license="fixture",
                )
            ],
        )
        nvd = plugin.model_copy(
            update={
                "title": "NVD title",
                "provenance": [
                    Provenance(
                        source="nvd",
                        fetched_at=NOW,
                        url="https://example.invalid/nvd",
                        license="NVD",
                    )
                ],
            }
        )
        expected_source = plugin_id if DEFAULT_SOURCE_PRECEDENCE[plugin_id] > 70 else "nvd"
        for first, second in ((plugin, nvd), (nvd, plugin)):
            merger = Merger()
            result = merger.merge(None, first, SourceContext.from_record(first))
            result = merger.merge(result.record, second, SourceContext.from_record(second))
            assert result.record.title == (
                f"{plugin_id} title" if expected_source == plugin_id else "NVD title"
            )
            assert any(
                item.field == "title" and item.source == expected_source
                for item in result.record.provenance
            )


def test_checker_query_ranges_combine_and_same_query_correction_replaces() -> None:
    def checker_range(version: str, fixed: str, *, source: str = "cisco_openvuln", url: str) -> AffectedRange:
        return AffectedRange(
            advisory_id="cisco-sa-ranges",
            product_id="cisco-iosxe",
            versions=VersionRange(exact=version, train=version.split(".")[0]),
            status="affected",
            fixed_versions=[fixed],
            provenance=[
                Provenance(
                    source=source,
                    fetched_at=NOW,
                    url=url,
                    license="fixture",
                    field="ranges",
                )
            ],
        )

    query_a = "https://checker.invalid/OSType/IOSXE?version=17.9.4&platformAlias=cat9k"
    query_b = "https://checker.invalid/OSType/IOSXE?version=17.3.5&platformAlias=cat9k"
    first = Advisory(
        id="cisco-sa-ranges",
        vendor_id="cisco",
        title="checker",
        ranges=[checker_range("17.9.4", "17.9.5", url=query_a)],
    )
    second = first.model_copy(
        update={"ranges": [checker_range("17.3.5", "17.3.6", url=query_b)]}
    )
    correction = first.model_copy(
        update={"ranges": [checker_range("17.9.4", "17.9.6", url=query_a)]}
    )
    csaf = first.model_copy(
        update={
            "ranges": [
                checker_range(
                    "18.1.1",
                    "18.1.2",
                    source="cisco_csaf",
                    url="https://cisco.invalid/csaf/cisco-sa-ranges.json",
                )
            ]
        }
    )

    merger = Merger()
    combined = merger.merge(None, first, SourceContext.from_record(first)).record
    combined = merger.merge(combined, second, SourceContext.from_record(second)).record
    combined = merger.merge(combined, correction, SourceContext.from_record(correction)).record
    combined = merger.merge(combined, csaf, SourceContext.from_record(csaf)).record
    combined = merger.merge(combined, correction, SourceContext.from_record(correction)).record

    assert len(combined.ranges) == 3
    assert {item.versions.exact for item in combined.ranges} == {"17.9.4", "17.3.5", "18.1.1"}
    assert next(item for item in combined.ranges if item.versions.exact == "17.9.4").fixed_versions == [
        "17.9.6"
    ]


def test_cvelist_archive_and_raw_urls_share_complete_publisher_range_scope() -> None:
    def advisory(url: str, fetched_at: datetime, ranges: list[AffectedRange]) -> Advisory:
        return Advisory(
            id="CVE-2026-ARCHIVE-CORRECTION",
            vendor_id="cisco",
            title="CVE correction",
            ranges=ranges,
            provenance=[
                Provenance(
                    source="cvelistv5",
                    fetched_at=fetched_at,
                    url=url,
                    license="CVE",
                    field="advisory",
                )
            ],
        )

    def affected(fixed: str, url: str, fetched_at: datetime) -> AffectedRange:
        return AffectedRange(
            advisory_id="CVE-2026-ARCHIVE-CORRECTION",
            product_id="cisco-iosxe",
            versions=VersionRange(exact="17.9.4", train="17.9"),
            status="affected",
            fixed_versions=[fixed],
            provenance=[
                Provenance(
                    source="cvelistv5",
                    fetched_at=fetched_at,
                    url=url,
                    license="CVE",
                    field="ranges",
                )
            ],
        )

    archive_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/archive.zip#CVE.json"
    raw_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/CVE.json"
    merger = Merger()
    old = advisory(archive_url, NOW, [affected("17.9.5", archive_url, NOW)])
    corrected = advisory(raw_url, NOW + timedelta(minutes=1), [])
    stale = advisory(raw_url, NOW - timedelta(minutes=1), [affected("17.9.5", raw_url, NOW - timedelta(minutes=1))])

    record = merger.merge(None, old, SourceContext.from_record(old)).record
    record = merger.merge(record, corrected, SourceContext.from_record(corrected)).record
    assert record.ranges == []
    record = merger.merge(record, stale, SourceContext.from_record(stale)).record
    assert record.ranges == []


def test_lower_source_not_affected_does_not_replace_vendor_range() -> None:
    url_vendor = "https://checker.invalid/OSType/IOSXE?version=17.9.4&platformAlias=cat9k"
    vendor = Advisory(
        id="cisco-sa-range-conflict",
        vendor_id="cisco",
        title="vendor",
        ranges=[checker_range_for_test("17.9.4", "affected", "cisco_openvuln", url_vendor)],
    )
    nvd = vendor.model_copy(
        update={
            "ranges": [checker_range_for_test("17.9.4", "not_affected", "nvd", "https://nvd.invalid/CVE")]
        }
    )
    merger = Merger()
    result = merger.merge(None, vendor, SourceContext.from_record(vendor))
    result = merger.merge(result.record, nvd, SourceContext.from_record(nvd))

    assert [item.status for item in result.record.ranges] == ["affected"]
    assert any(conflict.field.startswith("ranges[") for conflict in result.conflicts)


def test_authoritative_closed_scope_withdrawal_is_source_scoped() -> None:
    def advisory(
        source: str, url: str, scopes: list[ClosedScopeEvidence], fetched_at: datetime = NOW
    ) -> Advisory:
        return Advisory(
            id="cisco-sa-closed-scope",
            vendor_id="cisco",
            title="scope",
            closed_scopes=scopes,
            provenance=[
                Provenance(
                    source=source,
                    fetched_at=fetched_at,
                    url=url,
                    license="fixture",
                    field="advisory",
                )
            ],
        )

    source_url = "https://example.invalid/csaf/cisco-sa-closed-scope.json"
    scope = ClosedScopeEvidence(
        vendor_id="cisco",
        product_id="cisco-asa",
        hardware_models=["Cisco Firepower 1000 Series"],
        complete=True,
        explicit=True,
        provenance=[
            Provenance(
                source="cisco_csaf",
                fetched_at=NOW,
                url=source_url,
                license="fixture",
                field="closed_scope",
            )
        ],
    )
    merger = Merger()
    existing = merger.merge(
        None,
        advisory("cisco_csaf", source_url, [scope]),
        SourceContext("cisco_csaf", NOW, source_url, "fixture"),
    ).record

    unrelated = merger.merge(
        existing,
        advisory("nvd", "https://example.invalid/nvd/CVE", []),
        SourceContext("nvd", NOW, "https://example.invalid/nvd/CVE", "fixture"),
    ).record
    assert len(unrelated.closed_scopes) == 1

    stale_withdrawal = merger.merge(
        unrelated,
        advisory("cisco_csaf", f"{source_url}?revision=1", [], NOW - timedelta(days=1)),
        SourceContext("cisco_csaf", NOW - timedelta(days=1), f"{source_url}?revision=1", "fixture"),
    ).record
    assert len(stale_withdrawal.closed_scopes) == 1

    withdrawn = merger.merge(
        stale_withdrawal,
        advisory("cisco_csaf", f"{source_url}?revision=2", []),
        SourceContext("cisco_csaf", NOW, f"{source_url}?revision=2", "fixture"),
    ).record
    assert withdrawn.closed_scopes == []


def test_authoritative_platform_snapshot_replaces_but_partial_other_source_preserves() -> None:
    merger = Merger()
    source_url = "https://example.invalid/asa/compatibility"
    product = Product(
        id="cisco-asa",
        vendor_id="cisco",
        family="ASA",
        os="asa",
        scheme="cisco_asa",
        supported_platforms_by_release={"9.22(3)": ["Cisco Firepower 1000 Series"], "9.23(1)": ["Cisco Firepower 4100 Series"]},
        provenance=[
            Provenance(
                source="cisco_asa_compatibility",
                fetched_at=NOW,
                url=source_url,
                license="fixture",
                field="supported_platforms_by_release",
            )
        ],
    )
    current = merger.merge(
        None,
        product,
        SourceContext("cisco_asa_compatibility", NOW, source_url, "fixture"),
    ).record

    partial_other_source = product.model_copy(
        update={
            "family": "ASA updated metadata",
            "supported_platforms_by_release": {},
            "provenance": [
                Provenance(
                    source="cisco_csaf",
                    fetched_at=NOW,
                    url="https://example.invalid/csaf/asa",
                    license="fixture",
                    field="family",
                )
            ],
        }
    )
    preserved = merger.merge(
        current,
        partial_other_source,
        SourceContext("cisco_csaf", NOW, "https://example.invalid/csaf/asa", "fixture"),
    ).record
    assert preserved.supported_platforms_by_release == product.supported_platforms_by_release

    corrected = product.model_copy(
        update={
            "supported_platforms_by_release": {"9.22(3)": ["Cisco Firepower 1000 Series"]},
        }
    )
    replaced = merger.merge(
        current,
        corrected,
        SourceContext("cisco_asa_compatibility", NOW, source_url, "fixture"),
    ).record
    assert replaced.supported_platforms_by_release == {"9.22(3)": ["Cisco Firepower 1000 Series"]}

    withdrawn = product.model_copy(update={"supported_platforms_by_release": {}})
    cleared = merger.merge(replaced, withdrawn, SourceContext("cisco_asa_compatibility", NOW, source_url, "fixture")).record
    assert cleared.supported_platforms_by_release == {}


def test_distinct_advisory_id_is_not_replaced_by_cve_lookup() -> None:
    repository = InMemoryRepository()
    cve = "CVE-2026-SHARED-1"
    first = Advisory(id="cisco-sa-shared", vendor_id="cisco", title="Cisco")
    first = first.model_copy(update={"cves": [cve]})
    second = Advisory(id=cve, vendor_id="backbone", title="CVE backbone", cves=[cve])

    repository.merge_record(first, SourceContext("cisco_openvuln", NOW, "https://example.invalid/cisco", "Cisco"))
    repository.merge_record(second, SourceContext("cvelistv5", NOW, "https://example.invalid/cve", "CVE"))

    assert {record.id for record in repository.iter_records()} == {"cisco-sa-shared", cve}


def test_file_raw_store_is_content_addressed_and_immutable(tmp_path: Path) -> None:
    store = FileRawStore(tmp_path)
    raw = raw_document()

    first = store.put("fixture", raw)
    second = store.put("fixture", raw)

    assert first.content_hash == hashlib.sha256(raw.content).hexdigest()
    assert second.content_hash == first.content_hash
    assert store.get(first.content_hash).content == raw.content

    path = store.content_path(first.content_hash)
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="immutable"):
        store.put("fixture", raw)


def test_replay_reuses_immutable_raw_without_advancing_checkpoint(tmp_path: Path) -> None:
    raw_store = FileRawStore(tmp_path / "raw")
    connector = FixtureConnector([raw_document()])
    raw_store.put(connector.id, raw_document())
    repository = InMemoryRepository()

    result = RawReplayer(raw_store, repository).replay(connector)

    assert result.documents_seen == 1
    assert result.records_seen == 1
    assert repository.get_checkpoint(connector.id) is None
    assert [item.id for item in repository.iter_records()] == ["fixture-1"]


def test_worker_retries_without_advancing_checkpoint_on_failed_attempt() -> None:
    connector = FixtureConnector([raw_document()])
    repository = InMemoryRepository()
    attempts = 0

    def flaky_fetch(since: datetime | None):  # type: ignore[no-untyped-def]
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("temporary")
        yield from connector.documents

    connector.fetch = flaky_fetch  # type: ignore[method-assign]
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=2, initial_delay=0),
        clock=lambda: NOW,
        sleeper=lambda _: None,
    )

    result = worker.poll(connector.id)

    assert result.success
    assert attempts == 2
    checkpoint = repository.get_checkpoint(connector.id)
    assert checkpoint is not None
    assert checkpoint.last_success_at == NOW
    assert repository.get_source_status(connector.id).state == "healthy"


def test_worker_does_not_advance_checkpoint_when_all_retries_fail() -> None:
    connector = FixtureConnector([])

    def failing_fetch(since: datetime | None):  # type: ignore[no-untyped-def]
        raise TimeoutError("still down")
        yield  # pragma: no cover

    connector.fetch = failing_fetch  # type: ignore[method-assign]
    repository = InMemoryRepository()
    previous = Checkpoint(
        source_id=connector.id,
        cursor=NOW - timedelta(hours=1),
        last_success_at=NOW - timedelta(hours=1),
        generation=3,
    )
    repository.commit_checkpoint(previous)
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=2, initial_delay=0),
        clock=lambda: NOW,
        sleeper=lambda _: None,
    )

    result = worker.poll(connector.id)

    assert not result.success
    assert repository.get_checkpoint(connector.id) == previous
    assert repository.get_source_status(connector.id).state == "unavailable"


def test_optional_document_filter_runs_after_watermark_and_before_raw_persistence() -> None:
    class FilteringConnector(FixtureConnector):
        def __init__(self) -> None:
            super().__init__([raw_document()])
            self.callbacks: list[object | None] = []

        def accepts_document(self, raw, *, has_advisory=None):  # type: ignore[no-untyped-def]
            del raw
            self.callbacks.append(has_advisory)
            return False

    connector = FilteringConnector()
    repository = InMemoryRepository()
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=1),
        clock=lambda: NOW,
        sleeper=lambda _: None,
    )

    result = worker.poll(connector.id)

    assert result.success
    assert result.documents_seen == 1
    assert result.records_seen == 0
    assert repository.raw == {}
    assert repository.get_checkpoint(connector.id).cursor == NOW
    assert connector.callbacks == [None]


def test_document_filter_receives_advisory_lookup_only_on_incremental_poll() -> None:
    class IncrementalConnector(FixtureConnector):
        def __init__(self) -> None:
            super().__init__([raw_document()])
            self.callbacks: list[object | None] = []
            self.calls = 0

        def accepts_document(self, raw, *, has_advisory=None):  # type: ignore[no-untyped-def]
            del raw
            self.callbacks.append(has_advisory)
            return self.calls == 1

        def fetch(self, since):  # type: ignore[no-untyped-def]
            self.calls += 1
            yield from self.documents

    connector = IncrementalConnector()
    repository = InMemoryRepository()
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=1),
        clock=lambda: NOW,
        sleeper=lambda _: None,
    )

    assert worker.poll(connector.id).success
    assert worker.poll(connector.id).success
    assert connector.callbacks[0] is None
    assert callable(connector.callbacks[1])


def test_worker_run_once_respects_connector_schedule() -> None:
    connector = FixtureConnector([raw_document()])
    repository = InMemoryRepository()
    current = NOW
    worker = IngestWorker(
        {connector.id: connector},
        repository,
        retry=RetryPolicy(max_attempts=1),
        clock=lambda: current,
        sleeper=lambda _: None,
    )

    assert worker.run_once(now=current)
    assert worker.run_once(now=current + timedelta(seconds=1)) == []
    assert worker.run_once(now=current + timedelta(seconds=61))
    assert connector.calls == 2


def test_source_status_staleness_uses_each_connector_schedule() -> None:
    repository = InMemoryRepository()
    repository.set_source_status(
        SourceStatus(
            source_id="slow",
            enabled=True,
            allowed=True,
            state="healthy",
            schedule_seconds=1_000,
            stale_after_seconds=3_000,
            last_success_at=NOW - timedelta(seconds=3_001),
            updated_at=NOW,
        )
    )
    assert repository.source_status_at("slow", NOW).state == "stale"


def test_export_is_atomic_checksummed_stream_and_excludes_raw(tmp_path: Path) -> None:
    repository = InMemoryRepository()
    repository.merge_record(
        Product(
            id="product",
            vendor_id="vendor",
            family="Fixture",
            os="fixture-os",
            scheme="fixture",
        ),
        SourceContext(
            source="fixture",
            fetched_at=NOW,
            url="https://example.invalid/product",
            license="Fixture",
        ),
    )
    repository.put_raw("fixture", raw_document())
    repository.set_source_status(
        SourceStatus(
            source_id="blocked-oem",
            enabled=False,
            allowed=False,
            state="unapproved",
            detail="site terms require review",
            schedule_seconds=900,
            stale_after_seconds=2_700,
            updated_at=NOW,
            license_name="OEM terms",
            license_url="https://example.invalid/terms",
            attribution="OEM",
            redistribution="restricted",
            kind="advisory",
            vendor_scope=["arista"],
            operator_excluded=True,
        )
    )
    notice_dir = tmp_path / "notices"
    notice_dir.mkdir()
    (notice_dir / "CVE-terms.txt").write_text("full CVE terms notice", encoding="utf-8")
    exporter = DatasetExporter(repository, tmp_path / "exports", notice_dir=notice_dir)

    manifest = exporter.export(generated_at=NOW)

    assert manifest.record_count == 1
    dataset_path = tmp_path / "exports" / manifest.dataset_path
    assert manifest.sha256 == hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    lines = list(read_jsonl_dataset(dataset_path))
    assert lines[0]["record_type"] == "metadata"
    assert lines[0]["record"]["source_statuses"][0]["state"] == "unapproved"
    assert lines[0]["record"]["source_statuses"][0]["kind"] == "advisory"
    assert lines[0]["record"]["source_statuses"][0]["vendor_scope"] == ["arista"]
    assert lines[0]["record"]["license_notices"][0]["source_id"] == "blocked-oem"
    assert any(
        item.get("notice_text") == "full CVE terms notice"
        for item in lines[0]["record"]["license_notices"]
    )
    assert lines[1]["record_type"] == "product"
    assert "content" not in lines[1]
    assert not list(tmp_path.glob("*.tmp"))
    assert exporter.latest_manifest_path.read_text()


def test_nightly_export_runs_once_after_utc_window(tmp_path: Path) -> None:
    repository = InMemoryRepository()
    exporter = DatasetExporter(repository, tmp_path)
    scheduler = NightlyExportScheduler(exporter, hour_utc=2)

    assert scheduler.run_once(now=NOW.replace(hour=1)) is None
    assert scheduler.run_once(now=NOW.replace(hour=2)) is not None
    assert scheduler.run_once(now=NOW.replace(hour=3)) is None
    assert scheduler.run_once(now=NOW + timedelta(days=1, hours=-11)) is None
    assert scheduler.run_once(now=NOW + timedelta(days=1, hours=-10)) is not None


def test_heartbeat_is_timestamp_only_and_atomic(tmp_path: Path) -> None:
    heartbeat = tmp_path / "nested" / "heartbeat"

    write_heartbeat(heartbeat, now=NOW)

    assert heartbeat.read_text() == "2026-11-27T12:00:00+00:00\n"
    assert not list(heartbeat.parent.glob("*.tmp"))


def test_roll_up_metadata_keeps_recent_records_and_aggregates_old() -> None:
    records = [
        UsageMetadata(
            request_id="old",
            user_id="u1",
            key_id="k1",
            timestamp=NOW - timedelta(days=91),
            method="GET",
            route="/api/v1/advisories",
            status=200,
            latency_ms=10,
            response_size=20,
        ),
        UsageMetadata(
            request_id="recent",
            user_id="u1",
            key_id="k1",
            timestamp=NOW - timedelta(days=1),
            method="GET",
            route="/api/v1/advisories",
            status=200,
            latency_ms=12,
            response_size=22,
        ),
    ]

    rollups, retained = roll_up_metadata(records, now=NOW, retention_days=90)

    assert len(rollups) == 1
    assert rollups[0].request_count == 1
    assert rollups[0].day == date(2026, 8, 28)
    assert [item.request_id for item in retained] == ["recent"]


def test_roll_up_store_deletes_only_after_persisting_rollups() -> None:
    class Store:
        def __init__(self) -> None:
            self.deleted = False
            self.saved = []

        def iter_usage_before(self, cutoff):  # type: ignore[no-untyped-def]
            yield UsageMetadata(
                request_id="old",
                user_id="u1",
                timestamp=NOW - timedelta(days=91),
                method="GET",
                route="/health",
                status=200,
                latency_ms=1,
                response_size=2,
            )

        def upsert_daily_rollups(self, rollups):  # type: ignore[no-untyped-def]
            self.saved = list(rollups)

        def delete_usage_before(self, cutoff):  # type: ignore[no-untyped-def]
            self.deleted = True

    store = Store()
    assert roll_up_store(store, now=NOW) == 1
    assert store.saved and store.deleted




def test_export_includes_required_source_notices_outside_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest = DatasetExporter(InMemoryRepository(), tmp_path / "exports").export(generated_at=NOW)

    full_notices = {
        item["source_id"]: item["notice_text"]
        for item in manifest.license_notices
        if "notice_text" in item
    }
    assert "MITRE" in full_notices["notice:CVE-terms"]
    assert "endoflife.date" in full_notices["notice:endoflife-date-MIT"]



def test_hosted_epss_retains_scores_only_for_tracked_vendor_cves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "cisco")
    data = Path(__file__).parent / "fixtures" / "connectors" / "epss_scores.csv"

    def serve_scores(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=data.read_bytes(), request=request)

    repository = InMemoryRepository()
    repository.merge_record(
        Advisory(id="cisco-test", vendor_id="cisco", title="Cisco fixture", cves=["CVE-2024-20338"]),
        SourceContext("fixture", NOW, "https://example.test/cisco", "fixture"),
    )
    with httpx.Client(transport=httpx.MockTransport(serve_scores)) as client:
        connector = FirstEpssConnector(client=client)
        poll = IngestWorker({connector.id: connector}, repository, clock=lambda: NOW).poll(connector.id)

    assert poll.success
    assert [record.cve_id for record in repository.iter_records() if isinstance(record, Enrichment)] == [
        "CVE-2024-20338"
    ]



def test_worker_polls_a_previously_excluded_source_after_approval() -> None:
    connector = FixtureConnector([raw_document()])
    connector.license = license_for("restricted")
    repository = InMemoryRepository()
    connectors = {connector.id: connector}

    excluded = IngestWorker(
        connectors, repository, policy=PublicationPolicy(public=True), clock=lambda: NOW,
    )
    assert excluded.run_once() == []
    assert repository.get_source_status(connector.id).state == "unapproved"

    approved = IngestWorker(
        connectors,
        repository,
        policy=PublicationPolicy(public=True, reviewed_source_ids=frozenset({connector.id})),
        clock=lambda: NOW,
    )
    results = approved.run_once()
    assert len(results) == 1 and results[0].success
    assert repository.get_source_status(connector.id).state == "healthy"
    assert repository.get_checkpoint(connector.id) is not None
