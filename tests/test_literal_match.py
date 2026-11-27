from __future__ import annotations

from osak.core.models import (
    Advisory,
    AffectedRange,
    Asset,
    Condition,
    Dataset,
    MatchRequest,
    Product,
    Vendor,
    VersionRange,
)
from osak.match import match_assets
from osak.versions import get_scheme


def _dataset() -> Dataset:
    return Dataset(
        vendors=[Vendor(id="cisco", name="Cisco")],
        products=[
            Product(
                id="cisco-fmc",
                vendor_id="cisco",
                family="FMC",
                os="fmc",
                scheme="cisco_literal",
            )
        ],
        advisories=[
            Advisory(
                id="CISCO-LITERAL-001",
                vendor_id="cisco",
                title="FMC literal release",
                ranges=[
                    AffectedRange(
                        advisory_id="CISCO-LITERAL-001",
                        product_id="cisco-fmc",
                        versions=VersionRange(exact="7.4.1"),
                        hardware_models=["Firepower 4100"],
                        status="affected",
                        conditions=[Condition(feature="feature_x")],
                    ),
                    AffectedRange(
                        advisory_id="CISCO-LITERAL-001",
                        product_id="cisco-fmc",
                        versions=VersionRange(exact="7.4.2"),
                        hardware_models=["Firepower 4100"],
                        status="fixed",
                    ),
                ],
            )
        ],
    )


def test_literal_scheme_accepts_publisher_releases() -> None:
    scheme = get_scheme("cisco_literal")
    assert scheme is not None
    assert scheme.normalize("7.4.1") == "7.4.1"
    assert scheme.normalize("2.10.1.159") == "2.10.1.159"


def test_literal_scheme_only_supports_exact_ranges() -> None:
    scheme = get_scheme("cisco_literal")
    assert scheme is not None

    assert scheme.in_range("7.4.1", VersionRange(exact="7.4.1")) is True
    assert scheme.in_range("7.4.2", VersionRange(exact="7.4.1")) is False
    assert scheme.in_range("7.4.1", VersionRange(lower="7.4.0", upper="7.4.9")) is None
    assert scheme.in_range("7.4.1", VersionRange()) is None
    assert scheme.in_range("7.4.1a", VersionRange(exact="7.4.1")) is None
    assert scheme.compare("7.4.1", "7.4.2") is None


def test_literal_match_requires_exact_release_hardware_and_condition() -> None:
    response = match_assets(
        _dataset(),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="fmc-affected",
                    vendor="cisco",
                    product="cisco-fmc",
                    model="Firepower 4100",
                    version="7.4.1",
                    features=["feature_x"],
                ),
                Asset(
                    asset_ref="fmc-fixed",
                    vendor="cisco",
                    product="cisco-fmc",
                    model="Firepower 4100",
                    version="7.4.2",
                    features=["feature_x"],
                ),
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "affected"
    assert response.results[1].findings[0].verdict == "not_affected"


def test_literal_match_preserves_unknown_for_unsupported_or_unqualified_evidence() -> None:
    response = match_assets(
        _dataset(),
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="unsupported",
                    vendor="cisco",
                    product="cisco-fmc",
                    model="Firepower 4100",
                    version="7.4.1a",
                    features=["feature_x"],
                ),
                Asset(
                    asset_ref="wrong-hardware",
                    vendor="cisco",
                    product="cisco-fmc",
                    model="Firepower 1000",
                    version="7.4.2",
                    features=["feature_x"],
                ),
                Asset(
                    asset_ref="missing-condition",
                    vendor="cisco",
                    product="cisco-fmc",
                    model="Firepower 4100",
                    version="7.4.1",
                ),
            ]
        ),
    )
    assert [result.findings[0].verdict for result in response.results] == [
        "unknown",
        "unknown",
        "unknown",
    ]


def test_unlisted_literal_version_cannot_be_cleared_by_a_default() -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [AffectedRange(
        advisory_id="CISCO-LITERAL-001", product_id="cisco-fmc", versions=VersionRange(exact="7.4.1"),
        status="affected", default_status="not_affected",
    )]
    request = MatchRequest(assets=[Asset(asset_ref="unknown", vendor="cisco", os="FMC", version="7.4.3")])
    assert match_assets(dataset, request).results[0].findings[0].verdict == "unknown"


def test_literal_match_does_not_extrapolate_default_or_interval_ranges() -> None:
    dataset = _dataset()
    dataset.advisories[0].ranges = [
        AffectedRange(
            advisory_id="CISCO-LITERAL-001",
            product_id="cisco-fmc",
            versions=VersionRange(lower="7.4.0", upper="7.4.9"),
            status="affected",
        ),
        AffectedRange(
            advisory_id="CISCO-LITERAL-001",
            product_id="cisco-fmc",
            versions=VersionRange(),
            status="not_affected",
            default_status="not_affected",
        ),
    ]
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[
                Asset(
                    asset_ref="interval",
                    vendor="cisco",
                    product="cisco-fmc",
                    version="7.4.1",
                    features=["feature_x"],
                )
            ]
        ),
    )
    assert response.results[0].findings[0].verdict == "unknown"


def test_literal_match_preserves_ambiguous_product_identity() -> None:
    dataset = _dataset()
    dataset.products.append(
        Product(
            id="cisco-ftd",
            vendor_id="cisco",
            family="FMC",
            os="fmc",
            scheme="cisco_literal",
        )
    )
    response = match_assets(
        dataset,
        MatchRequest(
            assets=[Asset(asset_ref="ambiguous", vendor="cisco", version="7.4.1")]
        ),
    )
    assert response.results[0].status == "unresolved"
    assert response.results[0].findings[0].verdict == "unknown"
