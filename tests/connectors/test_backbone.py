from __future__ import annotations

import gzip
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from osak.connectors.base import RawDocument
from osak.connectors.cisa_kev import CisaKevConnector
from osak.connectors.common import ConnectorError, configured_vendor_scope
from osak.connectors.cvelistv5 import CveListV5Connector
from osak.connectors.first_epss import FirstEpssConnector
from osak.connectors.nvd import NvdConnector

FIXTURES = Path(__file__).parent.parent / "fixtures" / "connectors"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def json_response(request: httpx.Request, body: bytes, *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, headers={"content-type": "application/json"}, content=body, request=request)


def cve_baseline_archive() -> bytes:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(
            "cvelistV5-main/cves/2024/20xxx/CVE-2024-20338.json",
            fixture("cve_cisco_2024_20338.json"),
        )
        stream.writestr("cvelistV5-main/README.md", b"not a CVE record")
    return archive.getvalue()


@pytest.mark.parametrize("nested", [False, True], ids=["flat", "publisher-daily-wrapper"])
def test_cvelist_full_bootstrap_downloads_each_cve_from_the_recursive_tree(nested: bool) -> None:
    calls: list[httpx.Request] = []
    archive = cve_baseline_archive()
    if nested:
        wrapper = io.BytesIO()
        with zipfile.ZipFile(wrapper, "w") as outer:
            outer.writestr("cves.zip", archive)
        archive = wrapper.getvalue()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == "api.github.com":
            return json_response(
                request,
                json.dumps(
                    {
                        "published_at": "2026-11-27T11:24:34Z",
                        "assets": [
                            {
                                "name": "2026-11-27_all_CVEs_at_midnight.zip.zip",
                                "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/test/baseline.zip",
                            }
                        ]
                    }
                ).encode(),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/zip"},
            content=archive,
            request=request,
        )

    connector = CveListV5Connector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    documents = list(connector.fetch(None))
    assert all(doc.fetched_at.isoformat() == "2026-11-27T00:00:00+00:00" for doc in documents)

    assert len(documents) == 1
    assert documents[0].url.endswith("#cvelistV5-main/cves/2024/20xxx/CVE-2024-20338.json")
    assert documents[0].media_type == "application/json"
    assert len(calls) == 2


def test_empty_cve_archive_cannot_establish_the_initial_checkpoint() -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("README.md", b"no CVE payload")
    content.seek(0)
    with pytest.raises(ConnectorError, match="no CVE documents"):
        list(CveListV5Connector()._iter_archive(content, "https://example.org/archive.zip", datetime.now(UTC)))


def test_cvelist_old_cursor_rebuilds_from_baseline_instead_of_returning_a_gap() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == "raw.githubusercontent.com":
            return json_response(request, fixture("cve_delta_log.json"))
        return httpx.Response(
            200,
            headers={"content-type": "application/zip"},
            content=cve_baseline_archive(),
            request=request,
        )

    connector = CveListV5Connector(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        bootstrap_url="https://github.com/CVEProject/cvelistV5/releases/download/test/baseline.zip",
    )
    documents = list(connector.fetch(datetime(2026, 9, 1, tzinfo=UTC)))

    assert len(documents) == 1
    assert [call.url.host for call in calls] == ["raw.githubusercontent.com", "github.com"]


def test_cvelist_reuses_the_same_midnight_archive_across_hourly_releases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "baseline.zip"
    archive.write_bytes(cve_baseline_archive())
    base = "https://github.com/CVEProject/cvelistV5/releases/download/"
    filename = "2026-11-27_all_CVEs_at_midnight.zip"
    cached = base + "cve_2026-11-27_1400Z/" + filename
    current = base + "cve_2026-11-27_1500Z/" + filename
    baseline = datetime(2026, 11, 27, tzinfo=UTC)
    (tmp_path / "baseline.zip.json").write_text(
        json.dumps({"archive_url": cached, "fetched_at": baseline.isoformat()})
    )

    def reject_download(request: httpx.Request) -> httpx.Response:
        pytest.fail("The midnight archive is already cached")

    with httpx.Client(transport=httpx.MockTransport(reject_download)) as client:
        connector = CveListV5Connector(client=client, bootstrap_path=archive)
        monkeypatch.setattr(connector, "_latest_baseline_info", lambda: (current, baseline))
        document, = connector.fetch(None)
    assert document.url.startswith(cached + "#")
    assert document.fetched_at == baseline


def test_cvelist_delta_only_accepts_the_publisher_raw_host() -> None:
    assert CveListV5Connector._publisher_link(
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/20xxx/CVE-2024-20338.json"
    )
    assert CveListV5Connector._publisher_link("https://example.test/CVE-2024-20338.json") is None


def test_configured_vendor_scope_preserves_full_default_and_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("OSAK_VENDOR_SCOPE", raising=False)
    assert configured_vendor_scope() is None
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "Cisco,fortinet")
    assert configured_vendor_scope() == frozenset({"cisco", "fortinet"})
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "cisco,unknown")
    with pytest.raises(ValueError, match="OSAK_VENDOR_SCOPE"):
        configured_vendor_scope()


def test_cvelist_scope_accepts_cna_vendor(monkeypatch) -> None:
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "cisco,arista")
    connector = CveListV5Connector()
    raw = RawDocument(
        url="https://example.test/CVE-2024-20338.json",
        fetched_at=datetime.now(UTC),
        content=fixture("cve_cisco_2024_20338.json"),
    )
    assert connector.accepts_document(raw)


def test_cvelist_scope_callback_keeps_out_of_scope_correction(monkeypatch) -> None:
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "fortinet")
    connector = CveListV5Connector()
    raw = RawDocument(
        url="https://example.test/CVE-2024-20338.json",
        fetched_at=datetime.now(UTC),
        content=fixture("cve_cisco_2024_20338.json"),
    )
    assert connector.accepts_document(raw) is False
    assert connector.accepts_document(raw, has_advisory=lambda value: value == "CVE-2024-20338")


def test_nvd_scope_adds_verified_source_identifier(monkeypatch) -> None:
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "cisco")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return json_response(request, b'{"vulnerabilities": [], "totalResults": 0}')

    connector = NvdConnector(
        client=httpx.Client(transport=httpx.MockTransport(handler)), request_interval=0
    )
    list(connector.fetch(None))
    assert len(calls) == 1
    assert parse_qs(calls[0].url.query.decode())["sourceIdentifier"] == ["psirt@cisco.com"]


def test_nvd_scope_queries_each_configured_source_portfolio(monkeypatch) -> None:
    monkeypatch.setenv("OSAK_VENDOR_SCOPE", "fortinet,arista")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return json_response(request, b'{"vulnerabilities": [], "totalResults": 0}')

    connector = NvdConnector(
        client=httpx.Client(transport=httpx.MockTransport(handler)), request_interval=0
    )
    list(connector.fetch(None))
    assert {parse_qs(call.url.query.decode())["sourceIdentifier"][0] for call in calls} == {
        "psirt@arista.com",
        "psirt@fortinet.com",
    }


def test_cvelist_normalizes_arista_space_delimited_endpoints_as_a_range() -> None:
    raw = httpx.Response(
        200,
        content=fixture("cve_arista_2023_24511.json"),
        request=httpx.Request("GET", "https://example.test/CVE-2023-24511.json"),
    )
    connector = CveListV5Connector()
    records = list(
        connector.normalize(
            connector.document_from_response(raw, url="https://example.test/CVE-2023-24511.json")
        )
    )
    advisory = next(record for record in records if record.id == "CVE-2023-24511")
    affected = next(range_ for range_ in advisory.ranges if range_.product_id == "arista-eos")

    assert affected.versions.lower == "4.28.0"
    assert affected.versions.upper == "4.28.5.1M"
    assert affected.versions.include_lower is True
    assert affected.versions.include_upper is True
    assert affected.default_status == "not_affected"
    advisory_url = next(record for record in records if record.id == "CVE-2023-24511").urls[0]
    assert advisory_url.startswith("https://www.arista.com/")


def test_cvelist_preserves_unparseable_version_as_under_investigation() -> None:
    payload = json.loads(fixture("cve_arista_2023_24511.json"))
    payload["containers"]["cna"]["affected"][0]["versions"].append(
        {"version": "4.28.0 ???", "status": "affected"}
    )
    response = httpx.Response(
        200,
        content=json.dumps(payload).encode(),
        request=httpx.Request("GET", "https://example.test/CVE-2023-24511.json"),
    )
    records = list(
        CveListV5Connector().normalize(
            CveListV5Connector().document_from_response(
                response, url="https://example.test/CVE-2023-24511.json"
            )
        )
    )
    advisory = next(record for record in records if record.id == "CVE-2023-24511")
    malformed = next(range_ for range_ in advisory.ranges if range_.versions.exact == "4.28.0 ???")

    assert malformed.status == "under_investigation"
    assert malformed.default_status == "not_affected"


def test_cvelist_delta_is_gap_safe_at_cursor_and_deduplicates_replayed_ids() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.host == "raw.githubusercontent.com" and "deltaLog" in request.url.path:
            return json_response(request, fixture("cve_delta_log.json"))
        return json_response(request, fixture("cve_cisco_2024_20338.json"))

    connector = CveListV5Connector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    cursor = datetime(2026, 11, 27, 8, 0, tzinfo=UTC)
    documents = list(connector.fetch(cursor))

    assert [document.url for document in documents] == [
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/20xxx/CVE-2024-20338.json",
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/80xxx/CVE-2026-80243.json",
    ]
    assert documents[0].fetched_at.isoformat() == "2026-11-27T08:00:00+00:00"
    assert documents[1].fetched_at.isoformat() == "2026-11-27T08:05:00+00:00"
    assert len(calls) == 3
    # The cursor boundary is replayed intentionally; this is what makes a restart gap-safe.
    assert calls[0].url.path.endswith("deltaLog.json")


def test_cvelist_normalization_keeps_structured_facts_and_provenance() -> None:
    raw = httpx.Response(
        200,
        content=fixture("cve_cisco_2024_20338.json"),
        headers={"content-type": "application/json"},
        request=httpx.Request("GET", "https://example.test/CVE-2024-20338.json"),
    )
    connector = CveListV5Connector()
    document = connector.document_from_response(raw, url="https://example.test/CVE-2024-20338.json")

    records = list(connector.normalize(document))

    advisory = next(record for record in records if record.id == "CVE-2024-20338")
    products = [record for record in records if record.id == "cisco-iosxe"]
    vendors = [record for record in records if record.id == "cisco" and hasattr(record, "name")]
    assert products
    assert vendors
    assert advisory.id == "CVE-2024-20338"
    assert advisory.vendor_id == "cisco"
    assert advisory.severity == "high"
    assert advisory.cvss == 7.3
    assert advisory.urls == [
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secure-privesc-sYxQO6ds"
    ]
    assert {range_.status for range_ in advisory.ranges} == {"affected", "under_investigation"}
    upper_range = next(range_ for range_ in advisory.ranges if range_.versions.upper == "5.1.2.42")
    assert upper_range.versions.include_upper is False
    assert next(range_ for range_ in advisory.ranges if range_.product_id == "cisco-iosxe").versions.include_lower is True
    assert advisory.provenance[0].source == "cvelistv5"
    assert advisory.provenance[0].url == "https://example.test/CVE-2024-20338.json"


def test_kev_normalization_returns_only_exploitation_flag_and_date() -> None:
    connector = CisaKevConnector()
    request = httpx.Request("GET", connector.url)
    response = httpx.Response(200, content=fixture("cisa_kev.json"), request=request)
    document = connector.document_from_response(response)

    records = list(connector.normalize(document))

    assert len(records) == 1
    enrichment = records[0]
    assert enrichment.cve_id == "CVE-2024-20338"
    assert enrichment.kev is True
    assert enrichment.kev_date.isoformat() == "2024-06-12"
    assert enrichment.ransomware == "Unknown"
    assert enrichment.provenance[0].source == "cisa_kev"
    assert not hasattr(enrichment, "short_description")


def test_epss_bulk_fetch_uses_compressed_csv_and_normalizes_numeric_scores() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert str(request.url) == "https://epss.cyentia.com/epss_scores-current.csv.gz"
        return httpx.Response(
            200,
            headers={"content-type": "application/gzip"},
            content=gzip.compress(fixture("epss_scores.csv")),
            request=request,
        )

    connector = FirstEpssConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    documents = list(connector.fetch(None))
    records = [record for document in documents for record in connector.normalize(document)]

    assert len(documents) == 1
    assert [record.cve_id for record in records] == [
        "CVE-2024-20338",
        "CVE-2024-3094",
        "CVE-2024-3653",
    ]
    assert records[0].epss == 0.00123
    assert records[1].percentile == 0.9866
    assert records[2].epss_date.isoformat() == "2026-11-26"
    assert len(calls) == 1


def test_epss_api_fetch_is_bounded_and_does_not_walk_the_bulk_feed() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return json_response(request, fixture("epss_page_0.json"))

    connector = FirstEpssConnector(
        client=httpx.Client(transport=httpx.MockTransport(handler)), api_batch_size=2
    )
    documents = list(connector.fetch_for_cves(["CVE-2024-20338", "CVE-2024-3094", "CVE-2024-20338"]))

    assert len(documents) == 1
    assert parse_qs(calls[0].url.query.decode())["cve"] == ["CVE-2024-20338,CVE-2024-3094"]


def test_nvd_fetches_incremental_pages_with_key_header_and_cursor_range() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        start = int(parse_qs(request.url.query.decode())["startIndex"][0])
        return json_response(request, fixture("nvd_page_0.json" if start == 0 else "nvd_page_1.json"))

    connector = NvdConnector(
        api_key="test-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        page_size=1,
        request_interval=0,
    )
    since = datetime(2026, 11, 26, 0, 0, tzinfo=UTC)
    documents = list(connector.fetch(since))
    records = [record for document in documents for record in connector.normalize(document)]

    assert len(documents) == 2
    assert [record.cve_id for record in records] == ["CVE-2024-20338", "CVE-2024-3094"]
    assert records[0].cvss == 7.3
    assert records[0].cpes == ["cpe:2.3:a:cisco:secure_client:*:*:*:*:*:linux:*:*"]
    for call in calls:
        query = parse_qs(call.url.query.decode())
        assert query["lastModStartDate"] == ["2026-11-26T00:00:00.000Z"]
        assert "apiKey" not in query
        assert call.headers["apiKey"] == "test-key"


def test_nvd_normalization_ignores_descriptions_and_keeps_cvss_and_cpes() -> None:
    connector = NvdConnector()
    request = httpx.Request("GET", connector.url)
    response = httpx.Response(200, content=fixture("nvd_page_0.json"), request=request)
    document = connector.document_from_response(response)

    records = list(connector.normalize(document))

    assert len(records) == 1
    enrichment = records[0]
    assert enrichment.cvss_version == "3.1"
    assert enrichment.provenance[0].source == "nvd"
    assert not hasattr(enrichment, "descriptions")


def test_nvd_initial_poll_uses_full_index_and_worker_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-fixture")
    requests = []

    def reply(request):
        requests.append(request)
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    connector = NvdConnector(client=httpx.Client(transport=httpx.MockTransport(reply)))
    assert len(list(connector.fetch(None))) == 1
    assert requests[0].headers["apiKey"] == "test-fixture"
    assert "lastModStartDate" not in requests[0].url.params
