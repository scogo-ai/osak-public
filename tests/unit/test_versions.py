from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Final

import pytest
from hypothesis import given
from hypothesis import strategies as st

from osak.core.models import VersionRange
from osak.versions import get_scheme

SCHEME_NAMES: Final[tuple[str, ...]] = (
    "cisco_ios",
    "cisco_iosxe",
    "cisco_nxos",
    "cisco_asa",
    "fortios",
    "arista_eos",
)

CISCO_CSAF_DIR = Path(__file__).parents[1] / "golden" / "cisco-csaf"


def _recorded_service_packs(path: Path, family: str) -> list[str]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    versions: list[str] = []

    def visit(node: object, current_family: str | None = None) -> None:
        if not isinstance(node, dict):
            return
        family_name = current_family
        if node.get("category") == "product_family":
            family_name = node.get("name") if isinstance(node.get("name"), str) else None
        if node.get("category") == "service_pack" and family_name == family:
            name = node.get("name")
            if isinstance(name, str):
                versions.append(name)
        for child in node.get("branches", []):
            visit(child, family_name)

    visit(payload.get("product_tree", {}))
    return versions


@pytest.mark.parametrize("name", SCHEME_NAMES)
def test_registry_returns_every_required_scheme(name: str) -> None:
    scheme = get_scheme(name)

    assert scheme is not None
    assert callable(scheme.parse)
    assert callable(scheme.normalize)
    assert callable(scheme.compare)
    assert callable(scheme.in_range)


def test_registry_returns_none_for_unknown_scheme() -> None:
    assert get_scheme("junos") is None
    assert get_scheme("") is None


@pytest.mark.parametrize(
    ("name", "value", "normalized", "train"),
    (
        ("cisco_ios", "15.2(7)e4", "15.2(7)E4", "15.2E"),
        ("cisco_iosxe", "17.9.4A", "17.9.4a", "17.9"),
        ("cisco_nxos", "7.0(3)i7(9)", "7.0(3)I7(9)", "7.0I7"),
        ("cisco_asa", "9.18.3", "9.18(3)", "9.18"),
        ("cisco_asa", "9.20.3.13", "9.20(3).13", "9.20"),
        ("cisco_asa", "9.20(3).13", "9.20(3).13", "9.20"),
        ("fortios", "v7.2.8,build2573", "7.2.8-build2573", "7.2"),
        ("arista_eos", "4.27.3.1m", "4.27.3.1M", "4.27"),
    ),
)
def test_vendor_examples_parse_to_canonical_versions(
    name: str, value: str, normalized: str, train: str
) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    parsed = scheme.parse(value)

    assert parsed is not None
    assert parsed.normalized == normalized
    assert parsed.train == train
    assert scheme.normalize(value) == normalized


@pytest.mark.parametrize(
    ("name", "left", "right"),
    (
        ("cisco_ios", "15.2(7)E3", "15.2(7)E4"),
        ("cisco_iosxe", "17.9.4", "17.9.4a"),
        ("cisco_nxos", "7.0(3)I7(8)", "7.0(3)I7(9)"),
        ("cisco_asa", "9.18(3)", "9.18(4)"),
        ("cisco_asa", "9.20(3)", "9.20(3).13"),
        ("fortios", "7.2.7", "7.2.8"),
        ("arista_eos", "4.27.3", "4.27.3.1"),
    ),
)
def test_same_train_versions_have_deterministic_order(name: str, left: str, right: str) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    assert scheme.compare(left, left) == 0
    assert scheme.compare(left, right) == -1
    assert scheme.compare(right, left) == 1


@pytest.mark.parametrize(
    ("name", "left", "right"),
    (
        ("cisco_ios", "15.2(7)E4", "15.2(7)S4"),
        ("cisco_iosxe", "17.9.4a", "17.3.5b"),
        ("cisco_nxos", "9.3(10)", "10.2(5)"),
        ("cisco_asa", "9.18(3)", "9.16(4)"),
        ("fortios", "7.2.8", "7.4.4"),
        ("arista_eos", "4.31.0F", "4.30.1M"),
    ),
)
def test_different_trains_are_not_comparable(name: str, left: str, right: str) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    assert scheme.compare(left, right) is None
    assert scheme.compare(right, left) is None


def test_arista_lifecycle_labels_share_train_but_conflict_is_unknown() -> None:
    scheme = get_scheme("arista_eos")
    assert scheme is not None

    assert scheme.parse("4.29.2") is not None
    assert scheme.parse("4.27.3.1") is not None
    phase_f = scheme.parse("4.29.2F")
    phase_m = scheme.parse("4.29.2M")
    assert phase_f is not None
    assert phase_m is not None
    assert phase_f.train == "4.29"
    assert phase_m.train == "4.29"
    assert scheme.compare("4.29.2F", "4.29.2M") is None
    assert scheme.compare("4.29.2", "4.29.2M") == 0
    assert scheme.in_range("4.29.2M", VersionRange(exact="4.29.2F")) is None


@pytest.mark.parametrize(
    ("name", "version", "bounds", "expected"),
    (
        (
            "fortios",
            "7.2.7",
            VersionRange(train="7.2", lower="7.2.5", upper="7.2.8"),
            True,
        ),
        (
            "fortios",
            "7.4.4",
            VersionRange(train="7.2", lower="7.2.5", upper="7.2.8"),
            False,
        ),
        (
            "fortios",
            "7.2.8",
            VersionRange(train="7.2", lower="7.2.8"),
            True,
        ),
        (
            "fortios",
            "7.2.8",
            VersionRange(train="7.2", lower="7.2.8", include_lower=False),
            False,
        ),
        (
            "cisco_iosxe",
            "17.9.4a",
            VersionRange(exact="17.9.4a"),
            True,
        ),
        (
            "cisco_iosxe",
            "17.3.5b",
            VersionRange(exact="17.9.4a"),
            False,
        ),
        (
            "arista_eos",
            "4.31.0F-1",
            VersionRange(train="4.31", upper="4.31.0F-1"),
            False,
        ),
    ),
)
def test_in_range_is_train_aware(
    name: str, version: str, bounds: VersionRange, expected: bool
) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    assert scheme.in_range(version, bounds) is expected


@pytest.mark.parametrize("name", SCHEME_NAMES)
def test_unparseable_versions_return_unknown_values(name: str) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    assert scheme.parse("not-a-version") is None
    assert scheme.normalize("not-a-version") is None
    assert scheme.compare("not-a-version", "1.0") is None
    assert scheme.in_range("not-a-version", VersionRange(exact="1.0")) is None


@st.composite
def valid_version_examples(draw: st.DrawFn) -> tuple[str, str]:
    branch = draw(st.integers(min_value=1, max_value=99))
    minor = draw(st.integers(min_value=0, max_value=99))
    patch = draw(st.integers(min_value=0, max_value=99))
    return f"{branch}.{minor}.{patch}", f"{branch}.{minor}.{patch}"


@pytest.mark.parametrize("name", ("fortios", "cisco_iosxe"))
@given(valid_version_examples())
def test_numeric_schemes_round_trip_canonical_version(name: str, values: tuple[str, str]) -> None:
    value, expected = values
    scheme = get_scheme(name)
    assert scheme is not None

    parsed = scheme.parse(value)
    assert parsed is not None
    assert parsed.normalized == expected
    assert scheme.normalize(parsed.normalized) == parsed.normalized
    assert scheme.compare(parsed.normalized, parsed.normalized) == 0
    assert scheme.in_range(parsed.normalized, VersionRange(exact=parsed.normalized)) is True


@pytest.mark.parametrize(
    ("name", "template"),
    (
        ("cisco_ios", "15.2({number})E{number}"),
        ("cisco_iosxe", "17.9.{number}a"),
        ("cisco_nxos", "9.3({number})"),
        ("cisco_asa", "9.18({number})"),
        ("fortios", "7.2.{number}"),
        ("arista_eos", "4.31.{number}"),
    ),
)
@given(number=st.integers(min_value=1, max_value=99))
def test_every_scheme_round_trips_generated_vendor_versions(
    name: str, template: str, number: int
) -> None:
    value = template.format(number=number)
    scheme = get_scheme(name)
    assert scheme is not None

    parsed = scheme.parse(value)
    assert parsed is not None
    assert scheme.normalize(value) == parsed.normalized
    assert scheme.compare(value, value) == 0
    assert scheme.in_range(value, VersionRange(exact=value)) is True


@pytest.mark.parametrize(
    ("name", "versions"),
    (
        ("cisco_iosxe", ("17.3.1", "17.3.5b", "17.3.9")),
        ("fortios", ("7.2.1", "7.2.5", "7.2.8")),
        ("arista_eos", ("4.31.0", "4.31.0F-1", "4.31.1M")),
    ),
)
def test_vendor_order_is_transitive(name: str, versions: tuple[str, str, str]) -> None:
    scheme = get_scheme(name)
    assert scheme is not None

    first, middle, last = versions
    assert scheme.compare(first, middle) == -1
    assert scheme.compare(middle, last) == -1
    assert scheme.compare(first, last) == -1


def test_eos_explicit_cross_train_bounds_from_cve_2026_2379() -> None:
    scheme = get_scheme("arista_eos")
    assert scheme is not None
    span = VersionRange(lower="4.30.0F", upper="4.31.0")
    assert scheme.in_range("4.30.8.1", span) is True
    assert scheme.in_range("4.31.0", span) is False
    assert scheme.in_range("4.29.2", span) is False
    assert scheme.in_range("4.31.0", VersionRange(lower="4.30.0F")) is False
    assert scheme.in_range("4.30.0", VersionRange(lower="4.31.0", upper="4.30.0")) is None


def test_asa_rebuild_versions_are_train_aware_and_disjoint() -> None:
    scheme = get_scheme("cisco_asa")
    assert scheme is not None

    assert scheme.compare("9.20.3.13", "9.20(3).13") == 0
    assert scheme.compare("9.20(3)", "9.20(3).13") == -1
    assert scheme.compare("9.20.3.13", "9.18.4.52") is None
    assert scheme.in_range("9.20.3.13", VersionRange(exact="9.20(3).13")) is True


@pytest.mark.parametrize(
    ("value", "normalized", "train"),
    (
        ("3.3.0SG", "3.3.0sg", "3.3"),
        ("3.3.0SG1", "3.3.0sg1", "3.3"),
        ("16.10.1s", "16.10.1s", "16.10"),
        ("17.12.1z1", "17.12.1z1", "17.12"),
    ),
)
def test_iosxe_publisher_legacy_and_rebuild_grammars(
    value: str,
    normalized: str,
    train: str,
) -> None:
    scheme = get_scheme("cisco_iosxe")
    assert scheme is not None

    parsed = scheme.parse(value)

    assert parsed is not None
    assert parsed.normalized == normalized
    assert parsed.train == train


def test_iosxe_legacy_train_ranges_do_not_widen_unparseable_values() -> None:
    scheme = get_scheme("cisco_iosxe")
    assert scheme is not None

    bounds = VersionRange(
        train="3.3",
        lower="3.3.0SG",
        upper="3.3.0SG1",
        include_upper=True,
    )
    assert scheme.in_range("3.3.0SG", bounds) is True
    assert scheme.in_range("3.3.0SG1", bounds) is True
    assert scheme.in_range("3.3.0SG-foo", bounds) is None
    assert scheme.in_range("3.3.0SG", VersionRange(upper="not-a-version")) is None


@pytest.mark.parametrize(
    ("value", "normalized", "train"),
    (
        ("10.2(1q)", "10.2(1Q)", "10.2"),
        ("10.3(4a)", "10.3(4A)", "10.3"),
        ("7.0(3)i7(9)", "7.0(3)I7(9)", "7.0I7"),
        ("6.0(2)A8(10a)", "6.0(2)A8(10A)", "6.0A8"),
    ),
)
def test_nxos_publisher_suffix_and_variant_grammars(
    value: str,
    normalized: str,
    train: str,
) -> None:
    scheme = get_scheme("cisco_nxos")
    assert scheme is not None

    parsed = scheme.parse(value)

    assert parsed is not None
    assert parsed.normalized == normalized
    assert parsed.train == train


def test_nxos_suffix_releases_compare_inside_base_train() -> None:
    scheme = get_scheme("cisco_nxos")
    assert scheme is not None

    assert scheme.compare("10.2(1)", "10.2(1q)") == -1
    assert scheme.compare("10.2(1q)", "10.2(2)") == -1
    assert scheme.in_range(
        "10.2(1q)", VersionRange(lower="10.2(1)", upper="10.2(2)")
    ) is True
    assert scheme.compare("7.0(3)I7(8)", "7.0(3)I7(9)") == -1
    assert scheme.compare("7.0(3)I7(9)", "7.0(3)F3(1)") is None


def test_known_nonoverlapping_cisco_trains_are_false_not_unknown() -> None:
    scheme = get_scheme("cisco_nxos")
    assert scheme is not None

    assert scheme.in_range(
        "10.3(1)", VersionRange(lower="10.2(1)", upper="10.2(9)"),
    ) is False
    assert scheme.in_range(
        "10.2(1q)", VersionRange(lower="10.3(1)", upper="10.3(8)"),
    ) is False
    assert scheme.in_range(
        "10.2(1q)", VersionRange(lower="10.2(1)", upper="not-a-version"),
    ) is None


@pytest.mark.parametrize(
    "path",
    sorted(CISCO_CSAF_DIR.glob("*.json.gz")),
    ids=lambda path: path.name,
)
def test_iosxe_csaf_product_tree_versions_are_parseable(path: Path) -> None:
    values = _recorded_service_packs(path, "Cisco IOS XE Software")
    if not values:
        pytest.skip("fixture has no IOS XE product family")
    scheme = get_scheme("cisco_iosxe")
    assert scheme is not None
    assert all(scheme.parse(value) is not None for value in values), values


@pytest.mark.parametrize(
    "path",
    sorted(CISCO_CSAF_DIR.glob("*.json.gz")),
    ids=lambda path: path.name,
)
def test_nxos_csaf_product_tree_versions_are_parseable(path: Path) -> None:
    values = _recorded_service_packs(path, "Cisco NX-OS Software")
    if not values:
        pytest.skip("fixture has no NX-OS product family")
    scheme = get_scheme("cisco_nxos")
    assert scheme is not None
    assert all(scheme.parse(value) is not None for value in values), values
