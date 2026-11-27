"""Deterministic advisory correlation and inventory identity resolution."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from urllib.parse import parse_qs, urlparse

from osak.core.models import (
    Advisory,
    AffectedRange,
    Asset,
    AssetResult,
    Condition,
    ConditionResult,
    Dataset,
    Enrichment,
    EoLRecord,
    Finding,
    HardwareModel,
    MatchRequest,
    MatchResponse,
    Priority,
    Product,
    Provenance,
    Resolution,
    ResolveRequest,
    ResolveResponse,
    SourceAvailability,
    Verdict,
    VersionRange,
)
from osak.versions.base import ParsedVersion, VersionScheme

from .dataset import load_dataset_jsonl

DatasetSource = Dataset | str | Path

_VERSION_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"\d+(?:\.\d+){1,3}"
    r"(?:\([^)]*\))?"
    r"(?:[A-Za-z][A-Za-z0-9]*)?"
    r"(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?"
    r"(?![A-Za-z0-9])"
)

_SEVERITY_ORDER: dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class _Identity:
    product: Product
    vendor_id: str


RangeVerdict = Literal["affected", "not_affected", "unknown", "no_match"]


@dataclass(frozen=True)
class _RangeResult:
    verdict: RangeVerdict
    reasons: tuple[str, ...]
    conditions: tuple[ConditionResult, ...]
    matched: bool


def _key(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _compact_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _matches_label(value: str, labels: Iterable[str]) -> bool:
    value_key = _key(value)
    value_compact = _compact_key(value)
    if not value_key:
        return False
    for label in labels:
        label_key = _key(label)
        if label_key == value_key or _compact_key(label) == value_compact:
            return True
    return False


def _contains_label(text: str, labels: Iterable[str]) -> bool:
    text_key = _key(text)
    if not text_key:
        return False
    text_tokens = text_key.split()
    for label in labels:
        label_key = _key(label)
        if not label_key:
            continue
        label_tokens = label_key.split()
        if label_key == text_key or any(
            text_tokens[index : index + len(label_tokens)] == label_tokens
            for index in range(len(text_tokens) - len(label_tokens) + 1)
        ):
            return True
        # Permit punctuation differences within one token (for example
        # ``FG-100F`` versus ``FG100F``) without allowing a short label such
        # as ``os`` to match an unrelated word.
        compact_label = _compact_key(label)
        if len(label_tokens) == 1 and compact_label in {
            _compact_key(token) for token in text_tokens
        }:
            return True
    return False


def _product_labels(product: Product) -> tuple[str, ...]:
    vendor_only = _compact_key(product.vendor_id)
    vendor_names = tuple(
        name for name in product.vendor_names if _compact_key(name) != vendor_only
    )
    return (product.id, product.family, product.os, *product.aliases, *vendor_names)


def _vendor_labels(dataset: Dataset, vendor_id: str) -> tuple[str, ...]:
    labels: list[str] = [vendor_id]
    labels.extend(
        alias
        for vendor in dataset.vendors
        if vendor.id == vendor_id
        for alias in (vendor.name, *vendor.aliases)
    )
    return tuple(labels)


def _vendor_ids(dataset: Dataset, value: str) -> list[str]:
    matches: list[str] = []
    for vendor in dataset.vendors:
        if _matches_label(value, (vendor.id, vendor.name, *vendor.aliases)):
            matches.append(vendor.id)
    # A producer may export products without a vendor catalog line.  The
    # product's vendor_id remains usable as an exact canonical identity, but a
    # free-text product match never bypasses vendor ambiguity.
    if not matches:
        product_vendor_ids = {
            product.vendor_id for product in dataset.products if _matches_label(value, (product.vendor_id,))
        }
        matches.extend(sorted(product_vendor_ids))
    return list(dict.fromkeys(matches))


def _model_records(dataset: Dataset, product: Product, model: str) -> list[HardwareModel]:
    return [
        record
        for record in dataset.models
        if record.product_id == product.id
        and _matches_label(model, (record.id, record.family, *record.aliases))
    ]


def _model_matches(dataset: Dataset, product: Product, model: str) -> bool:
    if _model_records(dataset, product, model):
        return True
    # The canonical product may have no model catalog entry.  In that case a
    # range's hardware_models are still compared directly below.
    return _matches_label(model, (product.id, product.family)) if not dataset.models else False


def _resolve_product(
    dataset: Dataset,
    *,
    vendor: str,
    product: str | None,
    model: str | None,
    os: str | None,
) -> tuple[_Identity | None, str]:
    vendor_matches = _vendor_ids(dataset, vendor)
    if len(vendor_matches) != 1:
        if not vendor_matches:
            return None, f"unknown vendor identity: {vendor}"
        return None, f"ambiguous vendor identity: {vendor}"
    vendor_id = vendor_matches[0]
    candidates = [item for item in dataset.products if item.vendor_id == vendor_id]

    if product is not None:
        exact_id = [item for item in candidates if _matches_label(product, (item.id,))]
        if exact_id:
            candidates = exact_id
        else:
            candidates = [item for item in candidates if _matches_label(product, _product_labels(item))]
        if not candidates:
            return None, f"unknown product identity: {product}"

    if os is not None:
        candidates = [item for item in candidates if _matches_label(os, (item.os, item.family))]
        if not candidates:
            return None, f"product and OS identity do not agree: {os}"

    if model is not None:
        if any(len(_model_records(dataset, item, model)) > 1 for item in candidates):
            return None, f"ambiguous hardware model identity: {model}"
        model_candidates = [item for item in candidates if _model_matches(dataset, item, model)]
        if model_candidates:
            candidates = model_candidates
        elif product is None:
            return None, f"unknown hardware model identity: {model}"

    if len(candidates) != 1:
        if not candidates:
            return None, "no product identity matched the asset"
        return None, "ambiguous product identity"
    return _Identity(product=candidates[0], vendor_id=vendor_id), "product identity resolved"


def _get_scheme(name: str) -> VersionScheme | None:
    try:
        from osak import versions

        factory = getattr(versions, "get_scheme", None)
        if not callable(factory):
            return None
        scheme = factory(name)
    except (ImportError, KeyError, ValueError, TypeError):
        return None
    if scheme is None:
        return None
    return cast(VersionScheme, scheme)


def _safe_in_range(scheme: VersionScheme, value: str, bounds: VersionRange) -> bool | None:
    try:
        return scheme.in_range(value, bounds)
    except (AttributeError, AssertionError, IndexError, RuntimeError, TypeError, ValueError):
        return None


def _safe_normalize(scheme: VersionScheme, value: str) -> str | None:
    try:
        return scheme.normalize(value)
    except (AttributeError, AssertionError, IndexError, RuntimeError, TypeError, ValueError):
        return None


def _safe_parse(scheme: VersionScheme, value: str) -> ParsedVersion | None:
    try:
        return scheme.parse(value)
    except (AttributeError, AssertionError, IndexError, RuntimeError, TypeError, ValueError):
        return None


def _safe_compare(scheme: VersionScheme, left: str, right: str) -> int | None:
    try:
        return scheme.compare(left, right)
    except (AttributeError, AssertionError, IndexError, RuntimeError, TypeError, ValueError):
        return None


def _extract_normalized_version(scheme: VersionScheme, value: str) -> str | None:
    direct = _safe_normalize(scheme, value.strip())
    if direct is not None:
        return direct
    for match in _VERSION_TOKEN.finditer(value):
        normalized = _safe_normalize(scheme, match.group(0))
        if normalized is not None:
            return normalized
    return None


def _condition_status(condition: Condition, features: Sequence[str] | None) -> ConditionResult:
    if not condition.reviewed and condition.method == "llm_extracted":
        return ConditionResult(feature=condition.feature, status="unknown")
    if not condition.required:
        return ConditionResult(feature=condition.feature, status="satisfied")
    if features is None:
        return ConditionResult(feature=condition.feature, status="unknown")
    feature_key = _compact_key(condition.feature)
    feature_keys = {_compact_key(feature) for feature in features}
    status = "satisfied" if feature_key in feature_keys else "unsatisfied"
    if status == "unsatisfied" and condition.method == "parsed":
        # Parsed configuration evidence is scoped and may not describe the
        # caller's complete configuration. Missing a parsed feature therefore
        # preserves unknown instead of clearing an advisory finding.
        status = "unknown"
    return ConditionResult(
        feature=condition.feature,
        status=cast(Literal["satisfied", "unsatisfied"], status),
    )


def _evaluate_range(
    scheme: VersionScheme | None,
    asset: Asset,
    affected_range: AffectedRange,
) -> _RangeResult:
    if scheme is None:
        return _RangeResult(
            "unknown",
            ("version scheme is unavailable",),
            (),
            False,
        )
    in_range = _safe_in_range(scheme, asset.version, affected_range.versions)
    if in_range is None:
        return _RangeResult(
            "unknown",
            ("version could not be parsed or compared by the configured scheme",),
            (),
            False,
        )
    if not in_range:
        return _RangeResult(
            "no_match",
            ("version does not match the advisory range",),
            (),
            False,
        )

    conditions = tuple(_condition_status(condition, asset.features) for condition in affected_range.conditions)
    condition_reasons = tuple(
        f"condition '{condition.feature}' is {condition.status}" for condition in conditions
    )
    if any(condition.status == "unknown" for condition in conditions):
        return _RangeResult(
            "unknown",
            (*condition_reasons, "one or more advisory conditions lack supporting evidence"),
            conditions,
            True,
        )
    if any(condition.status == "unsatisfied" for condition in conditions):
        return _RangeResult(
            "not_affected",
            (*condition_reasons, "an advisory prerequisite is not satisfied"),
            conditions,
            True,
        )
    if affected_range.status == "affected":
        return _RangeResult(
            "affected",
            (*condition_reasons, "version is within an affected advisory range"),
            conditions,
            True,
        )
    if affected_range.status in {"fixed", "not_affected"}:
        return _RangeResult(
            "not_affected",
            (*condition_reasons, f"advisory range is marked {affected_range.status}"),
            conditions,
            True,
        )
    return _RangeResult(
        "unknown",
        (*condition_reasons, "advisory applicability is under investigation"),
        conditions,
        True,
    )


def _hardware_range_applies(dataset: Dataset, asset: Asset, affected_range: AffectedRange) -> bool | None:
    if not affected_range.hardware_models:
        return True
    if asset.model is None:
        return None
    matching_models = [
        model
        for model in dataset.models
        if _matches_label(asset.model, (model.id, model.family, *model.aliases))
    ]
    if len(matching_models) > 1:
        return None
    model_key = _compact_key(asset.model)
    for hardware_model in affected_range.hardware_models:
        if model_key == _compact_key(hardware_model):
            return True
        for model in dataset.models:
            if model.id == hardware_model and model_key in {
                _compact_key(model.id),
                _compact_key(model.family),
                *(_compact_key(alias) for alias in model.aliases),
            }:
                return True
    return False


def _advisory_enrichments(by_cve: Mapping[str, Enrichment], advisory: Advisory) -> list[Enrichment]:
    return [by_cve[cve.casefold()] for cve in advisory.cves if cve.casefold() in by_cve]


def _priority(
    advisory: Advisory,
    enrichments: Sequence[Enrichment],
    blocked_fields: set[str] | None = None,
) -> Priority:
    blocked = blocked_fields or set()
    kev_values = [
        enrichment.kev
        for enrichment in enrichments
        if enrichment.kev is not None and "kev" not in blocked
    ]
    epss_values = [
        enrichment.epss
        for enrichment in enrichments
        if enrichment.epss is not None and "epss" not in blocked
    ]
    cvss_values = [
        enrichment.cvss
        for enrichment in enrichments
        if enrichment.cvss is not None and "cvss" not in blocked
    ]
    return Priority(
        kev=True if any(kev_values) else False if kev_values else None,
        epss=max(epss_values) if epss_values else None,
        cvss=advisory.cvss if advisory.cvss is not None else max(cvss_values) if cvss_values else None,
        severity=advisory.severity,
    )


def _provenance(*groups: Iterable[Provenance]) -> list[Provenance]:
    result: list[Provenance] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for group in groups:
        for item in group:
            marker = (
                item.source,
                item.fetched_at.isoformat(),
                item.url,
                item.license,
                item.field,
                item.confidence,
            )
            if marker not in seen:
                seen.add(marker)
                result.append(item)
    return result


def _eol_records(dataset: Dataset, identity: _Identity, asset: Asset) -> list[EoLRecord]:
    records: list[EoLRecord] = []
    for record in dataset.eol:
        if record.product_id != identity.product.id:
            continue
        if record.model is not None and (
            asset.model is None or not _matches_label(asset.model, (record.model,))
        ):
            continue
        if record.version is not None and not eol_version_matches(
            identity.product.scheme, record.version, asset.version
        ):
            continue
        records.append(record)
    return records


def eol_version_matches(
    scheme_name: str,
    record_version: str | None,
    requested_version: str | None,
) -> bool:
    """Match exact lifecycle versions or a scheme-defined release train.

    Lifecycle feeds such as endoflife.date publish FortiOS records by cycle
    (for example ``7.2``), while callers provide a concrete release
    (``7.2.5``).  A scheme's ``normalize_train`` method is the shared source
    of truth for that relationship; unsupported/unparseable values remain
    unmatched rather than producing a false lifecycle result.
    """

    if record_version is None or requested_version is None:
        return True
    if record_version.strip().casefold() == requested_version.strip().casefold():
        return True
    scheme = _get_scheme(scheme_name)
    if scheme is None:
        return False
    parser = getattr(scheme, "parse", None)
    train_normalizer = getattr(scheme, "normalize_train", None)
    if parser is None or train_normalizer is None:
        return False
    parsed = parser(requested_version)
    record_train = train_normalizer(record_version)
    return parsed is not None and record_train is not None and parsed.train == record_train


def _severity_allowed(advisory: Advisory, minimum: str | None) -> bool:
    if minimum is None or minimum == "unknown":
        return True
    return _SEVERITY_ORDER[advisory.severity] >= _SEVERITY_ORDER[minimum]


def _is_kev(advisory: Advisory, enrichments: Sequence[Enrichment]) -> bool:
    return any(enrichment.kev is True for enrichment in enrichments)


_SOURCE_UNAVAILABLE_STATES = {
    "stale",
    "unavailable",
    "never_synced",
    "unknown",
    "failed",
    "running",
    "idle",
}


@dataclass(frozen=True)
class _SourceImpact:
    advisory: tuple[SourceAvailability, ...]
    enrichment: tuple[SourceAvailability, ...]
    eol: tuple[SourceAvailability, ...]


@dataclass(frozen=True)
class _ScopeClosure:
    reason: str
    provenance: tuple[Provenance, ...]


def _source_statuses(dataset: Dataset) -> list[SourceAvailability]:
    statuses = {status.source_id: status for status in dataset.source_statuses}
    for source_id in dataset.unavailable_sources:
        statuses.setdefault(
            source_id,
            SourceAvailability(source_id=source_id, state="unknown"),
        )
    return list(statuses.values())


def _source_is_relevant(status: SourceAvailability, vendor_id: str) -> bool:
    if status.operator_excluded or status.state in {"disabled", "unapproved"}:
        return False
    if status.state not in _SOURCE_UNAVAILABLE_STATES:
        return False
    if not status.vendor_scope or "*" in status.vendor_scope:
        return True
    scope = {_compact_key(vendor) for vendor in status.vendor_scope}
    return _compact_key(vendor_id) in scope


def _source_impact(dataset: Dataset, vendor_id: str) -> _SourceImpact:
    advisory: list[SourceAvailability] = []
    enrichment: list[SourceAvailability] = []
    eol: list[SourceAvailability] = []
    for status in _source_statuses(dataset):
        if not _source_is_relevant(status, vendor_id):
            continue
        if status.kind == "enrichment":
            enrichment.append(status)
        elif status.kind == "eol":
            eol.append(status)
        else:
            # A source with no known kind is legacy metadata.  Treat it as
            # applicability coverage so an unknown failure cannot clear a
            # device through an inferred not-affected result.
            advisory.append(status)
    return _SourceImpact(tuple(advisory), tuple(enrichment), tuple(eol))


def _source_reason(prefix: str, statuses: Sequence[SourceAvailability]) -> tuple[str, ...]:
    return tuple(f"{prefix} unavailable: {status.source_id}" for status in statuses)


def _blocked_enrichment_fields(
    enrichments: Sequence[Enrichment],
    statuses: Sequence[SourceAvailability],
) -> set[str]:
    blocked: set[str] = set()
    for enrichment in enrichments:
        if not statuses:
            continue
        if not enrichment.provenance:
            blocked.update({"kev", "epss", "cvss"})
            continue
        for provenance in enrichment.provenance:
            matching = [status for status in statuses if status.source_id == provenance.source]
            for status in matching:
                field = provenance.field.casefold()
                if field == "*":
                    blocked.update({"kev", "epss", "cvss"})
                if field.startswith("kev"):
                    blocked.add("kev")
                if field.startswith("epss"):
                    blocked.add("epss")
                if field.startswith("cvss") or "cpes" in field:
                    blocked.add("cvss")
    return blocked


def _fixed_scope_closure(
    advisory: Advisory,
    identity: _Identity,
    asset: Asset,
    scheme: VersionScheme,
    models: Sequence[str],
    scope_provenance: Sequence[Provenance],
    range_results: Sequence[_RangeResult],
    source_impact: _SourceImpact,
    reason: str,
) -> _ScopeClosure | None:
    """Require exact fixed evidence for every model in a closed universe."""

    if asset.model is not None or source_impact.advisory or not scope_provenance:
        return None
    if any(result.verdict in {"affected", "not_affected"} for result in range_results):
        return None
    if any(
        result.verdict == "unknown"
        and not any("hardware scope" in item for item in result.reasons)
        for result in range_results
    ):
        return None
    caller = _safe_parse(scheme, asset.version)
    if caller is None:
        return None
    normalized_models = [_compact_key(model) for model in models]
    if (
        not normalized_models
        or len(normalized_models) != len(set(normalized_models))
        or any(model in {"", "*", "unknown", "other"} for model in normalized_models)
    ):
        return None
    fixes_by_model: dict[str, set[str]] = {model: set() for model in normalized_models}
    fix_provenance: list[Provenance] = list(scope_provenance)
    for affected_range in advisory.ranges:
        if affected_range.product_id != identity.product.id:
            continue
        applicability = _safe_in_range(scheme, asset.version, affected_range.versions)
        if applicability is False:
            continue
        range_models = {_compact_key(model) for model in affected_range.hardware_models}
        query_aliases = {
            _compact_key(alias)
            for provenance in affected_range.provenance
            for key, values in parse_qs(urlparse(provenance.url).query).items()
            if key.casefold() in {"platformalias", "platform_alias"}
            for alias in values
        }
        unknown_models = set(range_models) - set(normalized_models) - query_aliases
        if unknown_models:
            return None
        range_models &= set(normalized_models)
        if affected_range.status in {"affected", "under_investigation"}:
            return None
        if affected_range.status not in {"fixed", "not_affected"}:
            continue
        if affected_range.conditions:
            return None
        if not affected_range.provenance or applicability is not True:
            continue
        fixed_values = list(affected_range.fixed_versions)
        if not fixed_values and affected_range.status == "fixed" and affected_range.versions.exact:
            fixed_values = [affected_range.versions.exact]
        parsed_fixes = [_safe_parse(scheme, fix) for fix in fixed_values]
        if not parsed_fixes or any(parsed is None for parsed in parsed_fixes):
            return None
        normalized_fixes = {parsed.normalized for parsed in parsed_fixes if parsed is not None}
        if normalized_fixes != {caller.normalized}:
            return None
        fix_provenance.extend(affected_range.provenance)
        for model in range_models:
            fixes_by_model[model].update(normalized_fixes)
    if any(fixes != {caller.normalized} for fixes in fixes_by_model.values()):
        return None
    return _ScopeClosure(reason=reason, provenance=tuple(fix_provenance))


def _closed_scope_not_affected(
    advisory: Advisory,
    identity: _Identity,
    asset: Asset,
    scheme: VersionScheme | None,
    range_results: Sequence[_RangeResult],
    source_impact: _SourceImpact,
) -> _ScopeClosure | None:
    """Use a producer-proven finite platform list and actual fixed ranges."""

    if asset.model is not None or scheme is None or source_impact.advisory:
        return None
    scopes = [
        scope
        for scope in advisory.closed_scopes
        if scope.vendor_id == identity.vendor_id and scope.product_id == identity.product.id
    ]
    if len(scopes) != 1:
        return None
    scope = scopes[0]
    if not scope.explicit or not scope.complete:
        return None
    return _fixed_scope_closure(
        advisory,
        identity,
        asset,
        scheme,
        scope.hardware_models,
        scope.provenance,
        range_results,
        source_impact,
        "closed platform scope proves the exact target applies to every listed model",
    )


def _supported_release_not_affected(
    identity: _Identity,
    asset: Asset,
    advisory: Advisory,
    scheme: VersionScheme | None,
    range_results: Sequence[_RangeResult],
    source_impact: _SourceImpact,
) -> _ScopeClosure | None:
    """Use an independently complete product release set conservatively."""

    if asset.model is not None or scheme is None or source_impact.advisory:
        return None
    if any(
        result.verdict in {"affected", "not_affected"}
        or (
            result.verdict == "unknown"
            and not any("hardware scope" in reason for reason in result.reasons)
        )
        for result in range_results
    ):
        return None
    caller = _safe_parse(scheme, asset.version)
    if caller is None:
        return None
    candidates: list[tuple[str, list[str]]] = []
    for release, models in identity.product.supported_platforms_by_release.items():
        parsed_release = _safe_parse(scheme, release)
        if parsed_release is not None and parsed_release.normalized == caller.normalized:
            candidates.append((parsed_release.normalized, models))
    if len(candidates) != 1:
        return None
    _, models = candidates[0]
    if (
        not models
        or len(models) != len(set(models))
        or any(model.casefold() in {"*", "unknown", "other"} for model in models)
    ):
        return None
    return _fixed_scope_closure(
        advisory,
        identity,
        asset,
        scheme,
        models,
        tuple(
            item
            for item in identity.product.provenance
            if item.field == "supported_platforms_by_release"
        ),
        range_results,
        source_impact,
        "complete product release platform set and unanimous exact fixes prove the target is safe",
    )


def _publisher_default(ranges: Sequence[AffectedRange]) -> Literal["affected", "not_affected"] | None:
    defaults = {item.default_status for item in ranges if item.default_status is not None}
    if len(defaults) != 1:
        return None
    default = next(iter(defaults))
    without_default = [item for item in ranges if item.default_status is None]
    if not without_default:
        return default

    # A CVE record can repeat the CNA's applicability in an ADP container.
    # Only an exact duplicate from the same record can use the CNA's default.
    excluded = {"default_status", "provenance"}
    explicit_evidence = {
        (item.model_dump_json(exclude=excluded), source.url, source.fetched_at)
        for item in ranges
        if item.default_status is not None
        for source in item.provenance
        if source.source == "cvelistv5"
    }
    for item in without_default:
        facts = item.model_dump_json(exclude=excluded)
        if not any(
            source.source == "cvelistv5"
            and (facts, source.url, source.fetched_at) in explicit_evidence
            for source in item.provenance
        ):
            return None
    return default


def _finding(
    dataset: Dataset,
    identity: _Identity,
    asset: Asset,
    advisory: Advisory,
    enrichments: Sequence[Enrichment],
) -> Finding:
    ranges = [item for item in advisory.ranges if item.product_id == identity.product.id]
    scheme = _get_scheme(identity.product.scheme)
    range_results: list[_RangeResult] = []
    applicable_ranges: list[AffectedRange] = []
    default_blocked = False
    for affected_range in ranges:
        # A model restriction on an unrelated release cannot make the
        # applicability of an otherwise explicit fix indeterminate.
        if scheme is not None and _safe_in_range(scheme, asset.version, affected_range.versions) is False:
            if affected_range.hardware_models:
                default_blocked = True
            range_results.append(_RangeResult("no_match", ("version is outside this range",), (), False))
            continue
        hardware_applies = _hardware_range_applies(dataset, asset, affected_range)
        if hardware_applies is None:
            range_results.append(
                _RangeResult(
                    "unknown",
                    ("advisory hardware scope cannot be resolved without a model",),
                    (),
                    False,
                )
            )
            continue
        if not hardware_applies:
            if affected_range.default_status is not None:
                default_blocked = True
            range_results.append(
                _RangeResult(
                    "no_match",
                    ("hardware model does not match the advisory scope",),
                    (),
                    False,
                )
            )
            continue
        result = _evaluate_range(scheme, asset, affected_range)
        range_results.append(result)
        if result.matched:
            applicable_ranges.append(affected_range)

    source_impact = _source_impact(dataset, identity.vendor_id)
    blocked_fields = _blocked_enrichment_fields(enrichments, source_impact.enrichment)
    eol = [] if source_impact.eol else _eol_records(dataset, identity, asset)
    advisory_reasons = _source_reason("relevant advisory source", source_impact.advisory)
    enrichment_reasons = _source_reason("relevant enrichment source", source_impact.enrichment)
    eol_reasons = _source_reason("lifecycle source", source_impact.eol)
    closure = _closed_scope_not_affected(
        advisory,
        identity,
        asset,
        scheme,
        range_results,
        source_impact,
    )
    if closure is None:
        closure = _supported_release_not_affected(
            identity,
            asset,
            advisory,
            scheme,
            range_results,
            source_impact,
        )
    verdict: Verdict
    default_applied = False
    if source_impact.advisory:
        verdict = "unknown"
    elif any(result.verdict == "affected" for result in range_results):
        verdict = "affected"
    elif closure is not None:
        verdict = "not_affected"
    elif any(result.verdict == "unknown" for result in range_results):
        verdict = "unknown"
    elif (
        ranges
        and not default_blocked
        and identity.product.scheme != "cisco_literal"
        and all(result.verdict == "no_match" for result in range_results)
    ):
        default = _publisher_default(ranges)
        verdict = default or "unknown"
        default_applied = default is not None
    elif any(result.verdict == "not_affected" for result in range_results):
        verdict = "not_affected"
    else:
        verdict = "unknown"

    reasons: list[str] = ["product identity resolved"]
    if closure is not None:
        reasons.append(closure.reason)
    if default_applied:
        reasons.append("publisher default status applies outside explicit ranges")
    if not ranges:
        reasons.append("no applicability evidence for the resolved product")
    for result in range_results:
        reasons.extend(result.reasons)
    reasons.extend(advisory_reasons)
    reasons.extend(enrichment_reasons)
    reasons.extend(eol_reasons)
    conditions: list[ConditionResult] = []
    seen_conditions: set[tuple[str, str]] = set()
    for result in range_results:
        for condition in result.conditions:
            marker = (condition.feature, condition.status)
            if marker not in seen_conditions:
                seen_conditions.add(marker)
                conditions.append(condition)

    fixed_versions: list[str] = []
    scheme = _get_scheme(identity.product.scheme)
    source_version = _safe_parse(scheme, asset.version) if scheme is not None else None
    candidate_versions: list[str] = []
    for affected_range in applicable_ranges:
        for version in affected_range.fixed_versions:
            if version not in candidate_versions:
                candidate_versions.append(version)
    if applicable_ranges and advisory.remediation is not None:
        for version in advisory.remediation.targets:
            if version not in candidate_versions:
                candidate_versions.append(version)
    if source_version is not None and scheme is not None:
        for candidate in candidate_versions:
            target_version = _safe_parse(scheme, candidate)
            if target_version is None or target_version.train != source_version.train:
                continue
            comparison = _safe_compare(scheme, asset.version, candidate)
            if comparison is not None and comparison < 0:
                fixed_versions.append(target_version.normalized)

    confidence = "high" if verdict in {"affected", "not_affected"} else "low"
    remediation = advisory.remediation
    return Finding(
        advisory_id=advisory.id,
        verdict=verdict,
        confidence=cast(Literal["high", "medium", "low"], confidence),
        reasons=list(dict.fromkeys(reasons)),
        conditions=conditions,
        fixed_versions=fixed_versions,
        recommended_target=fixed_versions[0] if fixed_versions else None,
        workaround=remediation.workaround if remediation is not None else None,
        priority=_priority(advisory, enrichments, blocked_fields),
        eol=eol,
        provenance=_provenance(
            advisory.provenance,
            closure.provenance if closure is not None else (),
            *(affected_range.provenance for affected_range in ranges),
            *(enrichment.provenance for enrichment in enrichments),
            *(record.provenance for record in eol),
        ),
    )


def _unresolved_result(asset: Asset, reason: str) -> AssetResult:
    return AssetResult(
        asset_ref=asset.asset_ref,
        status="unresolved",
        product_id=None,
        findings=[
            Finding(
                advisory_id=None,
                verdict="unknown",
                confidence="low",
                reasons=[reason],
            )
        ],
    )


def _coerce_dataset(dataset: DatasetSource) -> Dataset:
    if isinstance(dataset, Dataset):
        return dataset
    return load_dataset_jsonl(dataset)


def match_assets(dataset: DatasetSource, request: MatchRequest) -> MatchResponse:
    """Correlate assets against a normalized dataset without external I/O."""

    loaded = _coerce_dataset(dataset)
    enrichments_by_cve = {item.cve_id.casefold(): item for item in loaded.enrichments}
    results: list[AssetResult] = []
    for asset in request.assets:
        identity, reason = _resolve_product(
            loaded,
            vendor=asset.vendor,
            product=asset.product,
            model=asset.model,
            os=asset.os,
        )
        if identity is None:
            results.append(_unresolved_result(asset, reason))
            continue
        findings: list[Finding] = []
        for advisory in loaded.advisories:
            if advisory.vendor_id != identity.vendor_id:
                continue
            if not _severity_allowed(advisory, request.filters.min_severity):
                continue
            enrichments = _advisory_enrichments(enrichments_by_cve, advisory)
            if request.filters.kev_only and not _is_kev(advisory, enrichments):
                continue
            findings.append(_finding(loaded, identity, asset, advisory, enrichments))
        results.append(
            AssetResult(
                asset_ref=asset.asset_ref,
                status="resolved",
                product_id=identity.product.id,
                findings=findings,
            )
        )
    return MatchResponse(results=results)


def _resolve_raw_string(dataset: Dataset, raw: str) -> Resolution:
    product_candidates: list[Product] = []
    for product in dataset.products:
        if _contains_label(raw, _product_labels(product)):
            product_candidates.append(product)
    if not product_candidates:
        return Resolution(status="unresolved")
    product_ids = {product.id for product in product_candidates}
    if len(product_ids) != 1:
        return Resolution(status="unresolved")
    product = product_candidates[0]
    vendor_matches = _vendor_ids(dataset, product.vendor_id)
    if len(vendor_matches) != 1:
        return Resolution(status="unresolved")
    scheme = _get_scheme(product.scheme)
    if scheme is None:
        return Resolution(status="unresolved")
    version = _extract_normalized_version(scheme, raw)
    if version is None:
        return Resolution(status="unresolved")
    return Resolution(status="resolved", vendor=product.vendor_id, product_id=product.id, version=version)


def resolve_inventory(dataset: DatasetSource, request: ResolveRequest) -> ResolveResponse:
    """Resolve raw inventory descriptions to canonical product and version IDs."""

    loaded = _coerce_dataset(dataset)
    return ResolveResponse(results=[_resolve_raw_string(loaded, raw) for raw in request.raw_strings])
