from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from osak.core.models import (
    Advisory,
    AffectedRange,
    Asset,
    ClosedScopeEvidence,
    Condition,
    Dataset,
    Enrichment,
    EoLRecord,
    HardwareModel,
    MatchFilters,
    MatchRequest,
    Product,
    Provenance,
    Remediation,
    ResolveRequest,
    SourceAvailability,
    Vendor,
    VersionRange,
)
from osak.match import (
    DatasetChecksumError,
    DatasetLoadError,
    eol_version_matches,
    load_dataset,
    load_dataset_jsonl,
    match_assets,
    resolve_inventory,
)
from osak.versions.base import ParsedVersion

UTC_NOW = datetime(2026, 11, 27, tzinfo=UTC)


def test_fortios_eol_cycle_matches_concrete_release() -> None:
    assert eol_version_matches("fortios", "7.2", "7.2.5") is True
    assert eol_version_matches("fortios", "7.2", "7.4.5") is False


class NumericScheme:
    def parse(self, value: str) -> ParsedVersion | None:
        parts = value.strip().split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            return None
        return ParsedVersion(value.strip(), parts[0] + "." + parts[1], tuple(int(part) for part in parts))

    def normalize(self, value: str) -> str | None:
        parsed = self.parse(value)
        return parsed.normalized if parsed else None

    def compare(self, left: str, right: str) -> int | None:
        left_parsed = self.parse(left)
        right_parsed = self.parse(right)
        if not left_parsed or not right_parsed or left_parsed.train != right_parsed.train:
            return None
        return (left_parsed.order > right_parsed.order) - (left_parsed.order < right_parsed.order)

    def in_range(self, value: str, bounds: VersionRange) -> bool | None:
        parsed = self.parse(value)
        if parsed is None:
            return None
        if bounds.train is not None and bounds.train != parsed.train:
            return False
        if bounds.exact is not None:
            comparison = self.compare(value, bounds.exact)
            return comparison == 0 if comparison is not None else None
        if bounds.lower is not None:
            comparison = self.compare(value, bounds.lower)
            if comparison is None:
                return None
            if comparison < 0 or (comparison == 0 and not bounds.include_lower):
                return False
        if bounds.upper is not None:
            comparison = self.compare(value, bounds.upper)
            if comparison is None:
                return None
            if comparison > 0 or (comparison == 0 and not bounds.include_upper):
                return False
        return True


def _provenance(source: str = "fortinet") -> Provenance:
    return Provenance(
        source=source,
        fetched_at=UTC_NOW,
        url=f"https://example.test/{source}",
        license="facts",
    )


def _dataset(*, unavailable_sources: list[str] | None = None) -> Dataset:
    return Dataset(
        vendors=[Vendor(id="fortinet", name="Fortinet", aliases=["FortiNet"])],
        products=[
            Product(
                id="fortigate",
                vendor_id="fortinet",
                family="FortiGate",
                os="fortios",
                scheme="numeric",
                aliases=["FortiOS", "FortiGate OS"],
                vendor_names=["Fortinet FortiOS"],
            )
        ],
        advisories=[
            Advisory(
                id="FG-IR-0001",
                vendor_id="fortinet",
                title="SSL VPN issue",
                severity="high",
                cvss=8.1,
                cves=["CVE-2026-0001"],
                ranges=[
                    AffectedRange(
                        advisory_id="FG-IR-0001",
                        product_id="fortigate",
                        versions=VersionRange(train="7.2", lower="7.2.0", upper="7.2.8"),
                        status="affected",
                        fixed_versions=["7.2.8"],
                        conditions=[Condition(feature="ssl_vpn")],
                        provenance=[_provenance()],
                    )
                ],
                remediation=Remediation(
                    targets=["7.2.8"], workaround="Disable SSL VPN", url="https://example.test/fix"
                ),
                provenance=[_provenance()],
            )
        ],
        enrichments=[
            Enrichment(
                cve_id="CVE-2026-0001",
                kev=True,
                epss=0.91,
                cvss=8.1,
                provenance=[_provenance("cisa-kev")],
            )
        ],
        eol=[
            EoLRecord(
                id="eol-1",
                vendor_id="fortinet",
                product_id="fortigate",
                model="FG-100F",
                version="7.2.5",
                end_security=None,
                provenance=[_provenance("fortinet-eol")],
            )
        ],
        unavailable_sources=unavailable_sources or [],
    )


@pytest.fixture
def schemes(monkeypatch: pytest.MonkeyPatch) -> None:
    import osak.versions

    monkeypatch.setattr(
        osak.versions,
        "get_scheme",
        lambda name: NumericScheme() if name == "numeric" else None,
        raising=False,
    )


def test_match_assets_returns_affected_finding_with_fixes_priority_and_provenance(
    schemes: None,
) -> None:
    response = match_assets(
        _dataset(),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fw-1",
                    vendor="Fortinet",
                    product="FortiOS",
                    model="FG-100F",
                    version="7.2.5",
                    features=["SSL-VPN"],
                )
            ]
        ),
    )

    result = response.results[0]
    assert result.status == "resolved"
    assert result.product_id == "fortigate"
    finding = result.findings[0]
    assert finding.advisory_id == "FG-IR-0001"
    assert finding.verdict == "affected"
    assert finding.confidence == "high"
    assert finding.fixed_versions == ["7.2.8"]
    assert finding.recommended_target == "7.2.8"
    assert finding.workaround == "Disable SSL VPN"
    assert finding.priority.kev is True
    assert finding.priority.epss == pytest.approx(0.91)
    assert finding.priority.cvss == pytest.approx(8.1)
    assert finding.conditions[0].status == "satisfied"
    assert {item.source for item in finding.provenance} == {
        "fortinet",
        "cisa-kev",
        "fortinet-eol",
    }
    assert [record.id for record in finding.eol] == ["eol-1"]


def test_match_assets_is_fail_safe_for_unknown_conditions_and_unparseable_versions(
    schemes: None,
) -> None:
    unknown_features = match_assets(
        _dataset(),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fw-unknown-features",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                ),
                Asset(
                    asset_ref="fw-bad-version",
                    vendor="fortinet",
                    product="fortigate",
                    version="not-a-version",
                    features=["ssl_vpn"],
                ),
            ]
        ),
    )

    first, second = unknown_features.results
    assert first.findings[0].verdict == "unknown"
    assert first.findings[0].confidence == "low"
    assert first.findings[0].conditions[0].status == "unknown"
    assert second.findings[0].verdict == "unknown"
    assert any("could not be parsed" in reason for reason in second.findings[0].reasons)


def test_match_assets_returns_unresolved_for_ambiguous_identity_and_unknown_product(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.products.append(
        Product(
            id="fortios-alt",
            vendor_id="fortinet",
            family="FortiGate",
            os="fortios",
            scheme="numeric",
            aliases=["FortiOS"],
        )
    )
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(asset_ref="ambiguous", vendor="fortinet", version="7.2.5"),
                Asset(asset_ref="missing", vendor="fortinet", product="unknown", version="7.2.5"),
            ]
        ),
    )

    for result in response.results:
        assert result.status == "unresolved"
        assert result.product_id is None
        assert len(result.findings) == 1
        assert result.findings[0].advisory_id is None
        assert result.findings[0].verdict == "unknown"
        assert result.findings[0].confidence == "low"


def test_match_assets_applies_filters_and_unavailable_source_conservatively(
    schemes: None,
) -> None:
    response = match_assets(
        _dataset(unavailable_sources=["nvd"]),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fw-1",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ],
            filters=MatchFilters(min_severity="critical", kev_only=True),
        ),
    )
    assert response.results[0].findings == []

    response = match_assets(
        _dataset(unavailable_sources=["nvd"]),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fw-1",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ],
            filters=MatchFilters(kev_only=True),
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "unknown"
    assert any("nvd" in reason for reason in finding.reasons)


def test_resolve_inventory_uses_product_aliases_and_returns_unresolved_ambiguity(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.products.append(
        Product(
            id="fortios-alt",
            vendor_id="fortinet",
            family="FortiGate",
            os="fortios",
            scheme="numeric",
            aliases=["FortiOS"],
        )
    )
    response = resolve_inventory(
        dataset,
        ResolveRequest(
            raw_strings=[
                "Fortinet FortiOS Software, Version 7.2.5",
                "Fortinet FortiOS Software, Version unknown",
            ]
        ),
    )
    assert response.results[0].status == "unresolved"
    assert response.results[0].product_id is None
    assert response.results[1].status == "unresolved"

    dataset.products.pop()
    response = resolve_inventory(
        dataset,
        ResolveRequest(raw_strings=["Fortinet FortiOS Software, Version 7.2.5"]),
    )
    assert response.results[0].status == "resolved"
    assert response.results[0].vendor == "fortinet"
    assert response.results[0].product_id == "fortigate"
    assert response.results[0].version == "7.2.5"


def test_load_dataset_jsonl_checks_exact_file_checksum(tmp_path: Path) -> None:
    rows = [
        {"record_type": "vendor", "record": {"id": "fortinet", "name": "Fortinet"}},
        {
            "record_type": "product",
            "record": {
                "id": "fortigate",
                "vendor_id": "fortinet",
                "family": "FortiGate",
                "os": "fortios",
                "scheme": "numeric",
            },
        },
        {
            "record_type": "metadata",
            "record": {
                "source_statuses": [
                    {
                        "source_id": "nvd",
                        "state": "stale",
                        "kind": "enrichment",
                        "vendor_scope": ["*"],
                    }
                ]
            },
        },
    ]
    export = tmp_path / "dataset.jsonl"
    export.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    checksum = hashlib.sha256(export.read_bytes()).hexdigest()

    loaded = load_dataset_jsonl(export, checksum=checksum)
    assert loaded.vendors[0].id == "fortinet"
    assert loaded.products[0].scheme == "numeric"
    assert loaded.unavailable_sources == ["nvd"]
    assert loaded.source_statuses[0].source_id == "nvd"
    assert loaded.source_statuses[0].state == "stale"
    assert loaded.source_statuses[0].kind == "enrichment"

    with pytest.raises(DatasetChecksumError):
        load_dataset_jsonl(export, checksum="0" * 64)


def test_load_dataset_accepts_the_canonical_envelope(tmp_path: Path) -> None:
    content = b'\n{"record_type":"vendor","record":{"id":"fortinet","name":"Fortinet"}}\n'
    export = tmp_path / "dataset.jsonl"
    export.write_bytes(content)
    checksum = hashlib.sha256(content).hexdigest()

    loaded = load_dataset(export, f"sha256:{checksum}")
    assert loaded.vendors[0].name == "Fortinet"
    assert load_dataset_jsonl(export, checksum).vendors[0].id == "fortinet"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("not json\n", "invalid JSON"),
        ("[]\n", "must be a JSON object"),
        ('{"record_type":"nope","record":{}}\n', "unsupported dataset record type"),
        ('{"record_type":"vendor","record":[]}\n', "must contain an object"),
        (
            '{"record_type":"metadata","record":{"source_statuses":[1]}}\n',
            "invalid source status",
        ),
        ('{"record_type":"vendor","record":{"id":"x"}}\n', "invalid vendor record"),
    ],
)
def test_load_dataset_rejects_malformed_records(
    tmp_path: Path,
    payload: str,
    message: str,
) -> None:
    export = tmp_path / "bad.jsonl"
    export.write_text(payload, encoding="utf-8")
    with pytest.raises(DatasetLoadError, match=message):
        load_dataset_jsonl(export)


def test_load_dataset_rejects_invalid_checksum_arguments(tmp_path: Path) -> None:
    export = tmp_path / "dataset.jsonl"
    export.write_text(
        '{"record_type":"vendor","record":{"id":"x","name":"X"}}\n', encoding="utf-8"
    )
    with pytest.raises(DatasetChecksumError, match="checksum must"):
        load_dataset_jsonl(export, checksum="bad")
    with pytest.raises(DatasetChecksumError, match="checksum mismatch"):
        load_dataset_jsonl(export, checksum="0" * 64)


def test_match_assets_handles_hardware_scope_lifecycle_and_optional_conditions(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(lower="7.2.0", upper="7.2.8"),
            status="fixed",
            hardware_models=["FG-100F"],
            conditions=[Condition(feature="unused", required=False)],
        ),
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(exact="7.2.5"),
            status="under_investigation",
        ),
    ]
    missing_model = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(asset_ref="missing-model", vendor="fortinet", product="fortigate", version="7.2.5"),
                Asset(
                    asset_ref="wrong-model",
                    vendor="fortinet",
                    product="fortigate",
                    model="FG-200F",
                    version="7.2.5",
                ),
                Asset(
                    asset_ref="right-model",
                    vendor="fortinet",
                    product="fortigate",
                    model="FG-100F",
                    version="7.2.5",
                ),
            ]
        ),
    )
    assert missing_model.results[0].findings[0].verdict == "unknown"
    assert missing_model.results[1].findings[0].verdict == "unknown"
    assert missing_model.results[2].findings[0].verdict == "unknown"
    assert missing_model.results[2].findings[0].conditions[0].status == "satisfied"


def test_match_assets_resolves_by_model_and_is_unknown_without_a_scheme(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.models.append(
        HardwareModel(
            id="fg100f",
            vendor_id="fortinet",
            product_id="fortigate",
            family="FG-100F",
            aliases=["FG-100F"],
        )
    )
    resolved = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(asset_ref="by-model", vendor="fortinet", model="FG-100F", version="7.2.5"),
            ]
        ),
    )
    assert resolved.results[0].status == "resolved"
    assert resolved.results[0].product_id == "fortigate"

    dataset.products[0].scheme = "missing-scheme"
    unknown = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="no-scheme",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                ),
            ]
        ),
    )
    assert unknown.results[0].findings[0].verdict == "unknown"
    assert any("scheme is unavailable" in reason for reason in unknown.results[0].findings[0].reasons)


def test_resolve_inventory_infers_vendor_from_unique_product(schemes: None) -> None:
    response = resolve_inventory(
        _dataset(),
        ResolveRequest(raw_strings=["FortiOS 7.2.5", "a device with no version"]),
    )
    assert response.results[0].status == "resolved"
    assert response.results[0].vendor == "fortinet"
    assert response.results[1].status == "unresolved"


def test_resolve_inventory_ignores_vendor_only_competing_catalog_labels() -> None:
    dataset = Dataset(
        vendors=[Vendor(id="fortinet", name="Fortinet")],
        products=[
            Product(
                id="fortinet-fortiwlc",
                vendor_id="fortinet",
                family="Fortinet FortiWLC",
                os="Fortinet FortiWLC",
                scheme="unknown",
                vendor_names=["Fortinet"],
            ),
            Product(
                id="fortinet-fortios",
                vendor_id="fortinet",
                family="FortiGate",
                os="FortiOS",
                scheme="fortios",
                aliases=["FortiOS", "Fortinet FortiOS"],
                vendor_names=["Fortinet"],
            ),
        ],
    )
    response = resolve_inventory(
        dataset,
        ResolveRequest(raw_strings=["Fortinet FortiOS 7.2.4"]),
    )
    assert response.results[0].status == "resolved"
    assert response.results[0].product_id == "fortinet-fortios"
    assert response.results[0].version == "7.2.4"


def test_resolve_inventory_preserves_real_product_alias_ambiguity() -> None:
    dataset = Dataset(
        vendors=[Vendor(id="fortinet", name="Fortinet")],
        products=[
            Product(
                id="fortinet-fortios-a",
                vendor_id="fortinet",
                family="FortiGate",
                os="FortiOS",
                scheme="fortios",
                aliases=["FortiOS"],
            ),
            Product(
                id="fortinet-fortios-b",
                vendor_id="fortinet",
                family="FortiManager",
                os="FortiOS",
                scheme="fortios",
                aliases=["FortiOS"],
            ),
        ],
    )
    response = resolve_inventory(
        dataset,
        ResolveRequest(raw_strings=["Fortinet FortiOS 7.2.4"]),
    )
    assert response.results[0].status == "unresolved"


def test_match_assets_can_load_dataset_from_jsonl(tmp_path: Path, schemes: None) -> None:
    dataset = _dataset()
    rows: list[dict[str, object]] = []
    for record_type, records in (
        ("vendor", dataset.vendors),
        ("product", dataset.products),
        ("advisory", dataset.advisories),
        ("enrichment", dataset.enrichments),
        ("eol", dataset.eol),
    ):
        rows.extend(
            {"record_type": record_type, "record": record.model_dump(mode="json")}
            for record in records
        )
    export = tmp_path / "dataset.jsonl"
    export.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    response = match_assets(
        export,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fw-1",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "affected"


def test_nonmatching_version_or_train_is_unknown_not_not_affected(schemes: None) -> None:
    dataset = _dataset()
    older = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="older",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.1.9",
                    features=["ssl_vpn"],
                ),
                Asset(
                    asset_ref="newer",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.9",
                    features=["ssl_vpn"],
                ),
            ]
        ),
    )
    assert older.results[0].findings[0].verdict == "unknown"
    assert older.results[1].findings[0].verdict == "unknown"


def test_explicit_unaffected_range_proves_not_affected_and_default_is_unbounded(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(train="7.2", lower="7.2.8"),
            status="not_affected",
            default_status="not_affected",
        )
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fixed",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.8",
                    features=["ssl_vpn"],
                ),
                Asset(
                    asset_ref="older",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                ),
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "not_affected"
    assert response.results[1].findings[0].verdict == "not_affected"

    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(),
            status="not_affected",
        )
    ]
    default_response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="default",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    assert default_response.results[0].findings[0].verdict == "not_affected"


@pytest.mark.parametrize(
    ("duplicate_change", "expected"),
    [
        ({}, "not_affected"),
        ({"provenance": [_provenance("different-feed")]}, "unknown"),
        (
            {
                "provenance": [
                    _provenance("cvelistv5").model_copy(
                        update={"url": "https://example.test/another-cve"}
                    )
                ]
            },
            "unknown",
        ),
        ({"versions": VersionRange(lower="7.2.1", upper="7.2.4", include_upper=True)}, "unknown"),
        ({"default_status": "affected"}, "unknown"),
    ],
)
def test_only_exact_duplicates_from_the_same_cve_record_preserve_default(
    schemes: None,
    duplicate_change: dict[str, object],
    expected: str,
) -> None:
    dataset = _dataset()
    explicit = AffectedRange(
        advisory_id="FG-IR-0001",
        product_id="fortigate",
        versions=VersionRange(lower="7.2.0", upper="7.2.4", include_upper=True),
        status="affected",
        default_status="not_affected",
        provenance=[_provenance("cvelistv5")],
    )
    duplicate = explicit.model_copy(update={"default_status": None, **duplicate_change})
    dataset.advisories[0].ranges = [explicit, duplicate]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="outside-range",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == expected


def test_explicit_affected_default_applies_outside_complete_ranges(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(train="7.2", upper="7.2.8"),
            status="affected",
            default_status="affected",
        )
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="default-affected",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.9",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "affected"


def test_unparseable_range_blocks_an_explicit_default_fallback(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(exact="7.2.0 7.2.8"),
            status="under_investigation",
            default_status="not_affected",
        )
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="unknown-default",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def test_fix_options_are_limited_to_the_matched_train_and_upgrades(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].remediation = Remediation(targets=["7.2.4", "7.4.4", "7.2.8"])
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(train="7.2", lower="7.2.0", upper="7.2.8"),
            status="affected",
            fixed_versions=["7.2.8"],
        ),
        AffectedRange(
            advisory_id="FG-IR-0001",
            product_id="fortigate",
            versions=VersionRange(train="7.4", lower="7.4.0", upper="7.4.4"),
            status="affected",
            fixed_versions=["7.4.4"],
        ),
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="7.2",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=[],
                )
            ]
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "affected"
    assert finding.fixed_versions == ["7.2.8"]
    assert finding.recommended_target == "7.2.8"


def test_resolved_product_without_applicability_ranges_returns_unknown(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = []
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="missing-range",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                )
            ]
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "unknown"
    assert any("applicability evidence" in reason for reason in finding.reasons)


def test_ambiguous_hardware_alias_is_unresolved(schemes: None) -> None:
    dataset = _dataset()
    dataset.models.extend(
        [
            HardwareModel(
                id="fg100f-a",
                vendor_id="fortinet",
                product_id="fortigate",
                family="FG-100F",
            ),
            HardwareModel(
                id="fg100f-b",
                vendor_id="fortinet",
                product_id="fortigate",
                family="FG-100F",
            ),
        ]
    )
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="ambiguous-hardware",
                    vendor="fortinet",
                    product="fortigate",
                    model="FG-100F",
                    version="7.2.5",
                )
            ]
        ),
    )
    assert response.results[0].status == "unresolved"
    assert "ambiguous hardware" in response.results[0].findings[0].reasons[0]


def test_unrelated_advisory_source_failure_does_not_clear_positive_match(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.source_statuses = [
        SourceAvailability(
            source_id="arista_csaf",
            state="stale",
            kind="advisory",
            vendor_scope=["arista"],
        ),
        SourceAvailability(
            source_id="first_epss",
            state="unavailable",
            kind="enrichment",
            vendor_scope=["*"],
        ),
        SourceAvailability(
            source_id="fortios_eol",
            state="never_synced",
            kind="eol",
            vendor_scope=["fortinet"],
        ),
    ]
    dataset.enrichments[0].provenance = [_provenance("first_epss")]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fortinet-positive",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "affected"
    assert finding.priority.epss is None
    assert any("first_epss" in reason for reason in finding.reasons)
    assert any("fortios_eol" in reason for reason in finding.reasons)


def test_relevant_advisory_failure_blocks_positive_match_but_disabled_source_does_not(
    schemes: None,
) -> None:
    dataset = _dataset()
    dataset.source_statuses = [
        SourceAvailability(
            source_id="fortinet_psirt",
            state="stale",
            kind="advisory",
            vendor_scope=["fortinet"],
        )
    ]
    blocked = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="blocked",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    assert blocked.results[0].findings[0].verdict == "unknown"

    dataset.source_statuses = [
        SourceAvailability(
            source_id="fortinet_psirt",
            state="disabled",
            kind="advisory",
            vendor_scope=["fortinet"],
            operator_excluded=True,
        )
    ]
    allowed = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="allowed",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    assert allowed.results[0].findings[0].verdict == "affected"


def test_legacy_unavailable_source_without_scope_is_conservative(schemes: None) -> None:
    dataset = _dataset(unavailable_sources=["legacy-feed"])
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="legacy",
                    vendor="fortinet",
                    product="fortigate",
                    version="7.2.5",
                    features=["ssl_vpn"],
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def _closed_nxos_dataset(
    *,
    scope_models: list[str] | None = None,
    fixed_targets: dict[str, str] | None = None,
    complete: bool = True,
    explicit: bool = True,
    provenance: list[Provenance] | None = None,
) -> Dataset:
    models = ["nexus-3000", "nexus-9000"]
    scope_models = scope_models or models
    fixed_targets = fixed_targets or {model: "10.3(9)" for model in models}
    return Dataset(
        vendors=[Vendor(id="cisco", name="Cisco")],
        products=[
            Product(
                id="cisco-nxos",
                vendor_id="cisco",
                family="NX-OS",
                os="nxos",
                scheme="cisco_nxos",
            )
        ],
        advisories=[
            Advisory(
                id="CISCO-NXOS-CLOSED",
                vendor_id="cisco",
                title="Closed platform scope",
                ranges=[
                    range_item
                    for model in models
                    for range_item in (
                        AffectedRange(
                            advisory_id="CISCO-NXOS-CLOSED",
                            product_id="cisco-nxos",
                            versions=VersionRange(exact="10.2(1)"),
                            hardware_models=[model],
                            status="affected",
                        ),
                        AffectedRange(
                            advisory_id="CISCO-NXOS-CLOSED",
                            product_id="cisco-nxos",
                            versions=VersionRange(
                                exact=fixed_targets.get(model, "10.3(9)")
                            ),
                            hardware_models=[model],
                            status="fixed",
                            fixed_versions=[fixed_targets.get(model, "10.3(9)")],
                            provenance=[_provenance("cisco-fix")],
                        ),
                    )
                ],
                closed_scopes=[
                    ClosedScopeEvidence(
                        vendor_id="cisco",
                        product_id="cisco-nxos",
                        hardware_models=scope_models,
                        complete=complete,
                        explicit=explicit,
                        provenance=provenance if provenance is not None else [_provenance("cisco-csaf")],
                    )
                ],
            )
        ],
    )


def test_closed_scope_all_platform_fixes_clear_unqualified_newer_nxos() -> None:
    dataset = _closed_nxos_dataset()
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-unqualified",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "not_affected"
    assert any("closed platform scope" in reason for reason in finding.reasons)
    assert any(item.source == "cisco-csaf" for item in finding.provenance)


def test_closed_scope_derives_fixed_target_from_fixed_range_without_redundant_field() -> None:
    dataset = _closed_nxos_dataset()
    for affected_range in dataset.advisories[0].ranges:
        if affected_range.status == "fixed":
            affected_range.fixed_versions = []
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-range-only-fix",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "not_affected"


def test_closed_scope_uses_only_query_scoped_hardware_aliases() -> None:
    models = ["Cisco Nexus 3000 Series Switches", "Cisco Nexus 9000 Series Switches"]
    dataset = _closed_nxos_dataset(scope_models=models)
    aliases = {models[0]: "NEXUS3000", models[1]: "NEXUS9000"}
    for affected_range in dataset.advisories[0].ranges:
        model = affected_range.hardware_models[0]
        official = models[0] if model == "nexus-3000" else models[1]
        affected_range.hardware_models = [official, aliases[official]]
        if affected_range.status == "fixed":
            affected_range.provenance = [
                Provenance(
                    source="cisco-openvuln",
                    fetched_at=UTC_NOW,
                    url=f"https://example.test/check?platformAlias={aliases[official]}",
                    license="facts",
                )
            ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-query-alias",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "not_affected"

    for affected_range in dataset.advisories[0].ranges:
        if affected_range.status == "fixed":
            affected_range.provenance = [_provenance("cisco-openvuln")]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-unscoped-alias",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


@pytest.mark.parametrize(
    ("kwargs", "asset_version", "asset_model"),
    (
        ({"scope_models": ["nexus-3000"]}, "10.3(9)", None),
        ({"fixed_targets": {"nexus-3000": "10.3(9)", "nexus-9000": "10.4(1)"}}, "10.3(9)", None),
        ({"complete": False}, "10.3(9)", None),
        ({"explicit": False}, "10.3(9)", None),
        ({"provenance": []}, "10.3(9)", None),
        ({}, "not-a-version", None),
        ({}, "10.3(9)", "nexus-7000"),
    ),
)
def test_closed_scope_declines_partial_conflicting_or_unparseable_evidence(
    kwargs: dict[str, object],
    asset_version: str,
    asset_model: str | None,
) -> None:
    dataset = _closed_nxos_dataset(**kwargs)
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-conservative",
                    vendor="cisco",
                    product="cisco-nxos",
                    version=asset_version,
                    model=asset_model,
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def test_closed_scope_conflicting_or_unavailable_source_cannot_clear() -> None:
    dataset = _closed_nxos_dataset()
    dataset.source_statuses = [
        SourceAvailability(
            source_id="cisco-csaf",
            state="unavailable",
            kind="advisory",
            vendor_scope=["cisco"],
        )
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-source-unavailable",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def test_closed_scope_rejects_fixed_ranges_with_unsatisfied_conditions() -> None:
    dataset = _closed_nxos_dataset()
    for affected_range in dataset.advisories[0].ranges:
        if affected_range.status == "fixed":
            affected_range.conditions = [Condition(feature="bgp_configured")]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="nxos-conditional",
                    vendor="cisco",
                    product="cisco-nxos",
                    version="10.3(9)",
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def test_complete_product_release_platform_set_can_clear_unqualified_asa() -> None:
    models = ["asa-5500-x", "firepower-1000"]
    dataset = Dataset(
        vendors=[Vendor(id="cisco", name="Cisco")],
        products=[
            Product(
                id="cisco-asa",
                vendor_id="cisco",
                family="ASA",
                os="asa",
                scheme="cisco_asa",
                supported_platforms_by_release={"9.22.3": models},
                provenance=[
                    _provenance("cisco-compatibility").model_copy(
                        update={"field": "supported_platforms_by_release"}
                    )
                ],
            )
        ],
        advisories=[
            Advisory(
                id="CISCO-ASA-CLOSED",
                vendor_id="cisco",
                title="ASA compatibility scope",
                ranges=[
                    AffectedRange(
                        advisory_id="CISCO-ASA-CLOSED",
                        product_id="cisco-asa",
                        versions=VersionRange(exact="9.22.3"),
                        hardware_models=[model],
                        status="fixed",
                        fixed_versions=["9.22.3"],
                        provenance=[_provenance("cisco-csaf")],
                    )
                    for model in models
                ],
            )
        ],
    )
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="asa-unqualified",
                    vendor="cisco",
                    product="cisco-asa",
                    version="9.22.3",
                )
            ]
        ),
    )
    finding = response.results[0].findings[0]
    assert finding.verdict == "not_affected"
    assert any("complete product release platform set" in reason for reason in finding.reasons)
    assert {item.source for item in finding.provenance} >= {
        "cisco-compatibility",
        "cisco-csaf",
    }

    newer = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="asa-newer",
                    vendor="cisco",
                    product="cisco-asa",
                    version="9.22.4",
                )
            ]
        ),
    )
    assert newer.results[0].findings[0].verdict == "unknown"



def test_match_indexes_the_enrichment_dataset_once(schemes: None) -> None:
    class CountingEnrichments(list[Enrichment]):
        scans = 0

        def __iter__(self):
            self.scans += 1
            return super().__iter__()

    dataset = _dataset()
    enrichments = CountingEnrichments(dataset.enrichments)
    dataset.enrichments = enrichments
    request = MatchRequest(assets=[
        Asset(asset_ref="first", vendor="fortinet", product="fortigate", version="7.2.5"),
        Asset(asset_ref="second", vendor="fortinet", product="fortigate", version="7.2.5"),
    ])

    results = match_assets(dataset, request).results

    assert len(results) == 2
    assert all(result.findings[0].priority.kev is True for result in results)
    assert enrichments.scans == 1
