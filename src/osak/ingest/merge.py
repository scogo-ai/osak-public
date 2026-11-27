"""Deterministic field-level merging of normalized canonical records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

from osak.core.models import (
    Advisory,
    CanonicalRecord,
    Enrichment,
    EoLRecord,
    HardwareModel,
    Product,
    Provenance,
    Vendor,
)
from osak.ingest.types import Conflict

T = TypeVar("T", bound=CanonicalRecord)


DEFAULT_SOURCE_PRECEDENCE: dict[str, int] = {
    "vendor_psirt": 100,
    "vendor-psirt": 100,
    "vendor_cna": 90,
    "vendor-cna": 90,
    "cert_csaf": 80,
    "cert-csaf": 80,
    "nvd": 70,
    "aggregator": 50,
}

# Connector ids are the provenance values emitted by the production plugins.
# Keep this table explicit: relying on a caller-supplied role map meant normal
# worker scheduling silently treated these sources as precedence zero.
SOURCE_ID_PRECEDENCE: dict[str, int] = {
    "cvelistv5": 90,  # CNA-authored CVE records
    "cisco_csaf": 100,
    "cisco_openvuln": 100,
    "cisco_eox": 100,
    "fortinet_psirt_rss": 100,
    "fortinet_psirt_page": 100,
    "fortinet_cna": 90,
    "arista_csaf": 100,
    "nvd": 70,
    "cisa_kev": 50,
    "first_epss": 50,
    "endoflife_date_fortios": 50,
}

DEFAULT_SOURCE_PRECEDENCE.update(SOURCE_ID_PRECEDENCE)


@dataclass(frozen=True, slots=True)
class SourceContext:
    """Source metadata used to attribute a normalized record."""

    source: str
    fetched_at: datetime
    url: str
    license: str
    role: str | None = None
    confidence: str = "high"
    precedence: int | None = None

    @classmethod
    def from_record(cls, record: CanonicalRecord) -> SourceContext:
        provenance = getattr(record, "provenance", [])
        if not provenance and isinstance(record, Advisory):
            provenance = [
                item
                for affected_range in record.ranges
                for item in affected_range.provenance
            ]
        if not provenance:
            raise ValueError("a source context is required for a record without provenance")
        first = provenance[0]
        return cls(
            source=first.source,
            fetched_at=first.fetched_at,
            url=first.url,
            license=first.license,
            confidence=first.confidence,
        )


@dataclass(frozen=True, slots=True)
class MergeResult:
    record: CanonicalRecord
    conflicts: tuple[Conflict, ...]
    changed: bool


@dataclass(frozen=True, slots=True)
class _Candidate:
    value: Any
    source: str
    fetched_at: datetime
    precedence: int
    provenance: Provenance | None = None
    explicit_field: bool = False


class Merger:
    """Merge records with an explicit, deterministic field precedence.

    Precedence is evaluated independently for each field.  A high-precedence
    vendor PSIRT title can therefore coexist with lower-precedence enrichment
    fields that the PSIRT did not provide.  Disagreements are returned to the
    caller for durable conflict logging; they are never silently discarded.
    """

    def __init__(
        self,
        source_precedence: Mapping[str, int] | None = None,
        *,
        default_precedence: int = 0,
    ) -> None:
        self.source_precedence = dict(DEFAULT_SOURCE_PRECEDENCE)
        if source_precedence:
            self.source_precedence.update(source_precedence)
        self.default_precedence = default_precedence

    def merge(self, existing: CanonicalRecord | None, incoming: CanonicalRecord, context: SourceContext) -> MergeResult:
        incoming = _ensure_provenance(incoming, context)
        if existing is None:
            return MergeResult(self._annotate_field_provenance(incoming, context), (), True)
        if _record_kind(existing) != _record_kind(incoming) or _record_id(existing) != _record_id(incoming):
            raise ValueError("cannot merge canonical records with different identities")

        conflicts: list[Conflict] = []
        values: dict[str, Any] = {}
        merged_provenance = _merge_provenance(existing, incoming)
        for field_name in type(existing).model_fields:
            if field_name == "provenance":
                values[field_name] = merged_provenance
                continue
            old_value = getattr(existing, field_name)
            new_value = getattr(incoming, field_name)
            old_candidate = self._candidate(existing, field_name, old_value)
            new_candidate = self._candidate(incoming, field_name, new_value, context)
            merged, field_conflicts = self._merge_field(
                record_id=_record_id(existing),
                record_type=_record_kind(existing),
                field_name=field_name,
                old=old_candidate,
                new=new_candidate,
                now=context.fetched_at,
            )
            values[field_name] = merged
            conflicts.extend(field_conflicts)
            if winner := _winner_candidate(old_candidate, new_candidate, old_value, new_value):
                _append_field_provenance(merged_provenance, winner.provenance, field_name)

        if "provenance" in type(existing).model_fields:
            if isinstance(existing, (Vendor, Product, HardwareModel)):
                values["provenance"] = self._compact_catalog_provenance(
                    existing, incoming, values, context
                )
            else:
                values["provenance"] = merged_provenance

        merged_record = type(existing).model_validate(values)
        changed = merged_record.model_dump(mode="json") != existing.model_dump(mode="json")
        return MergeResult(merged_record, tuple(conflicts), changed)

    def _compact_catalog_provenance(
        self,
        existing: CanonicalRecord,
        incoming: CanonicalRecord,
        merged_values: dict[str, Any],
        context: SourceContext,
    ) -> list[Provenance]:
        """Keep bounded winning evidence for stable identity/catalog facts."""

        compact: list[Provenance] = []
        for field_name in type(existing).model_fields:
            if field_name == "provenance":
                continue
            old_value = getattr(existing, field_name)
            new_value = getattr(incoming, field_name)
            old_candidate = self._candidate(existing, field_name, old_value)
            new_candidate = self._candidate(incoming, field_name, new_value, context)
            winner = _catalog_winner(old_candidate, new_candidate, old_value, new_value)
            if winner.provenance is None:
                continue
            merged_value = merged_values.get(field_name)
            if isinstance(old_value, list) and isinstance(new_value, list) and isinstance(
                merged_value, list
            ) and all(not isinstance(item, BaseModel) for item in merged_value):
                _append_catalog_list_provenance(
                    existing,
                    compact,
                    field_name,
                    merged_value,
                    old_value,
                    new_value,
                    old_candidate,
                    new_candidate,
                )
                continue
            evidence = winner.provenance.model_copy(update={"field": field_name})
            if evidence not in compact:
                compact.append(evidence)
        return compact

    def _annotate_field_provenance(
        self, record: CanonicalRecord, context: SourceContext
    ) -> CanonicalRecord:
        if not hasattr(record, "provenance"):
            return record
        provenance = list(record.provenance)
        for field_name in type(record).model_fields:
            if field_name == "provenance":
                continue
            candidate = self._candidate(record, field_name, getattr(record, field_name), context)
            _append_field_provenance(provenance, candidate.provenance, field_name)
        return record.model_copy(update={"provenance": provenance})

    def _candidate(
        self,
        record: CanonicalRecord,
        field_name: str,
        value: Any,
        context: SourceContext | None = None,
    ) -> _Candidate:
        provenance = _field_provenance(record, field_name)
        if not provenance and isinstance(record, Advisory) and field_name == "ranges":
            # Only cvelistv5 advisory provenance is a complete range snapshot;
            # unrelated source records must not inherit its timestamp/source
            # when they omit ranges.
            provenance = [
                item
                for item in getattr(record, "provenance", [])
                if item.source == "cvelistv5" and item.field in {"advisory", "*"}
            ]
        if not provenance and isinstance(record, (Vendor, Product, HardwareModel)):
            provenance = list(getattr(record, "provenance", []))
        if provenance:
            selected = max(
                provenance,
                key=lambda item: (
                    self._precedence(item.source, context),
                    item.fetched_at,
                    item.source,
                ),
            )
            return _Candidate(
                value=value,
                source=selected.source,
                fetched_at=selected.fetched_at,
                precedence=self._precedence(selected.source, context),
                provenance=selected,
                explicit_field=(
                    selected.field == field_name
                    and not _has_generated_field_marker(record, selected)
                ),
            )
        if context is None:
            return _Candidate(value, "unknown", datetime.min.replace(tzinfo=UTC), self.default_precedence)
        fallback = Provenance(
            source=context.source,
            fetched_at=context.fetched_at,
            url=context.url,
            license=context.license,
            field="__inferred__",
            confidence=context.confidence,  # type: ignore[arg-type]
        )
        return _Candidate(
            value,
            context.source,
            context.fetched_at,
            self._precedence(context.source, context),
            fallback,
        )

    def _precedence(self, source: str, context: SourceContext | None = None) -> int:
        if context is not None and source == context.source and context.precedence is not None:
            return context.precedence
        if context is not None and source == context.source and context.role in self.source_precedence:
            return self.source_precedence[context.role]
        if source in self.source_precedence:
            return self.source_precedence[source]
        # Exact source ids commonly carry their role as a prefix.  This keeps
        # the default useful while allowing operators to provide exact values.
        for role, value in self.source_precedence.items():
            if source.startswith((f"{role}:", f"{role}_")):
                return value
        return self.default_precedence

    def _merge_field(
        self,
        *,
        record_id: str,
        record_type: str,
        field_name: str,
        old: _Candidate,
        new: _Candidate,
        now: datetime,
    ) -> tuple[Any, list[Conflict]]:
        if field_name in {"ranges", "closed_scopes"} and isinstance(old.value, list) and isinstance(new.value, list):
            return self._merge_ranges(
                record_id=record_id,
                record_type=record_type,
                old=old,
                new=new,
                now=now,
                field_name=field_name,
            )

        if _is_missing(old.value):
            return new.value, []
        if _is_missing(new.value):
            if field_name == "supported_platforms_by_release" and _is_authoritative_empty(new):
                if _is_missing(old.value) or _choose(old, new) is new:
                    return new.value, []
                return old.value, []
            return old.value, []
        if _json_value(old.value) == _json_value(new.value):
            return old.value, []

        winner = _choose(old, new)
        loser = new if winner is old else old
        conflict = Conflict(
            record_type=record_type,
            record_id=record_id,
            field=field_name,
            kept_value=_json_value(winner.value),
            incoming_value=_json_value(new.value),
            kept_source=winner.source,
            incoming_source=new.source,
            kept_precedence=winner.precedence,
            incoming_precedence=new.precedence,
            detected_at=now,
            losing_source=loser.source,
            losing_value=_json_value(loser.value),
        )
        # Scalar lists such as CVE ids and URLs are additive facts.  The
        # precedence still decides the order, while preserving a lower-source
        # value avoids losing useful cross-source identifiers.
        if isinstance(old.value, list) and isinstance(new.value, list) and all(
            not isinstance(item, BaseModel) for item in [*old.value, *new.value]
        ):
            return _union_scalars(old.value, new.value, winner is new), [conflict]
        if isinstance(old.value, BaseModel) and isinstance(new.value, BaseModel):
            nested = self._merge_nested(old.value, new.value, now)
            return nested, [conflict]
        return winner.value, [conflict]

    def _merge_ranges(
        self,
        *,
        record_id: str,
        record_type: str,
        old: _Candidate,
        new: _Candidate,
        now: datetime,
        field_name: str,
    ) -> tuple[list[Any], list[Conflict]]:
        """Combine independent source/query slices without erasing siblings.

        Cisco Software Checker calls are scoped by the full request URL.  A
        correction from the same source/query replaces that slice, while a
        different query or an independent CSAF source is additive.  A lower
        precedence correction cannot replace a higher-evidence slice.
        """

        old_ranges = list(old.value)
        new_ranges = list(new.value)
        old_groups = _group_ranges(old_ranges, old, field_name)
        new_groups = _group_ranges(new_ranges, new, field_name)
        result = list(old_ranges)
        conflicts: list[Conflict] = []

        if not old_ranges and new_ranges and old.provenance is not None:
            incoming_source = _range_source(new_ranges[0], new)
            if incoming_source == old.source:
                old_key = _candidate_order_key(old, self)
                incoming_key = max(_range_order_key(item, new, self) for item in new_ranges)
                if incoming_key < old_key:
                    scope = _range_scope(new_ranges[0], new, field_name)
                    if scope is not None:
                        conflicts.append(
                            _range_conflict(
                                record_type=record_type,
                                record_id=record_id,
                                scope=scope,
                                field_name=field_name,
                                kept=[],
                                incoming=new_ranges,
                                kept_source=old.source,
                                incoming_source=incoming_source,
                                kept_precedence=old_key[0],
                                incoming_precedence=incoming_key[0],
                                detected_at=now,
                            )
                        )
                    return result, conflicts

        if not new_ranges:
            scope = _range_scope(None, new, field_name)
            if scope is not None:
                scoped_old = [
                    item for item in result if _range_scope(item, old, field_name) == scope
                ]
                if scoped_old:
                    old_key = max(_range_order_key(item, old, self) for item in scoped_old)
                    new_key = _candidate_order_key(new, self)
                    if new_key < old_key:
                        conflicts.append(
                            _range_conflict(
                                record_type=record_type,
                                record_id=record_id,
                                scope=scope,
                                field_name=field_name,
                                kept=scoped_old,
                                incoming=[],
                                kept_source=_range_source(scoped_old[0], old),
                                incoming_source=new.source,
                                kept_precedence=old_key[0],
                                incoming_precedence=new_key[0],
                                detected_at=now,
                            )
                        )
                    else:
                        result = [
                            item for item in result if _range_scope(item, old, field_name) != scope
                        ]
            return result, conflicts

        for scope, incoming_ranges in new_groups.items():
            if scope is None:
                for item in incoming_ranges:
                    if _range_key(item) not in {_range_key(value) for value in result}:
                        result.append(item)
                continue
            existing_ranges = old_groups.get(scope, [])
            if not existing_ranges:
                for item in incoming_ranges:
                    semantic_matches = [
                        value for value in old_ranges if _range_semantic_key(value) == _range_semantic_key(item)
                    ]
                    if semantic_matches:
                        if any(_range_fact_key(value) == _range_fact_key(item) for value in semantic_matches):
                            continue
                        existing_rank = max(
                            _range_precedence(value, old, self) for value in semantic_matches
                        )
                        incoming_rank = _range_precedence(item, new, self)
                        if incoming_rank < existing_rank:
                            conflicts.append(
                                _range_conflict(
                                    record_type=record_type,
                                    record_id=record_id,
                                    scope=scope,
                                    field_name=field_name,
                                    kept=semantic_matches,
                                    incoming=[item],
                                    kept_source=_range_source(semantic_matches[0], old),
                                    incoming_source=_range_source(item, new),
                                    kept_precedence=existing_rank,
                                    incoming_precedence=incoming_rank,
                                    detected_at=now,
                                )
                            )
                            continue
                        if incoming_rank > existing_rank:
                            result = [
                                value
                                for value in result
                                if _range_semantic_key(value) != _range_semantic_key(item)
                            ]
                        conflicts.append(
                            _range_conflict(
                                record_type=record_type,
                                record_id=record_id,
                                scope=scope,
                                field_name=field_name,
                                kept=semantic_matches,
                                incoming=[item],
                                kept_source=_range_source(
                                    item if incoming_rank > existing_rank else semantic_matches[0],
                                    new if incoming_rank > existing_rank else old,
                                ),
                                incoming_source=_range_source(
                                    semantic_matches[0] if incoming_rank > existing_rank else item,
                                    old if incoming_rank > existing_rank else new,
                                ),
                                kept_precedence=(
                                    max(existing_rank, incoming_rank)
                                ),
                                incoming_precedence=(
                                    min(incoming_rank, existing_rank)
                                ),
                                detected_at=now,
                            )
                        )
                    if _range_key(item) not in {_range_key(value) for value in result}:
                        result.append(item)
                continue
            existing_rank = max(_range_precedence(item, old, self) for item in existing_ranges)
            incoming_rank = max(_range_precedence(item, new, self) for item in incoming_ranges)
            existing_key = max(_range_order_key(item, old, self) for item in existing_ranges)
            incoming_key = max(_range_order_key(item, new, self) for item in incoming_ranges)
            if incoming_key < existing_key:
                conflicts.append(
                    _range_conflict(
                        record_type=record_type,
                        record_id=record_id,
                                scope=scope,
                                field_name=field_name,
                        kept=existing_ranges,
                        incoming=incoming_ranges,
                        kept_source=_range_source(existing_ranges[0], old),
                        incoming_source=_range_source(incoming_ranges[0], new),
                        kept_precedence=existing_rank,
                        incoming_precedence=incoming_rank,
                        detected_at=now,
                    )
                )
                continue
            # Replace only this source/query slice.  Other source/query slices
            # stay untouched, including independent CSAF applicability.
            result = [
                item
                for item in result
                if _range_scope(item, old, field_name) != scope
            ]
            result.extend(incoming_ranges)

        return result, conflicts

    def _merge_nested(self, old: BaseModel, new: BaseModel, now: datetime) -> BaseModel:
        old_data = old.model_dump(mode="python")
        new_data = new.model_dump(mode="python")
        for name, value in new_data.items():
            if _is_missing(old_data.get(name)):
                old_data[name] = value
        return type(old).model_validate(old_data)


def _record_kind(record: CanonicalRecord) -> str:
    return {
        Vendor: "vendor",
        Product: "product",
        HardwareModel: "hardware_model",
        Advisory: "advisory",
        Enrichment: "enrichment",
        EoLRecord: "eol",
    }[type(record)]


def _record_id(record: CanonicalRecord) -> str:
    if isinstance(record, Enrichment):
        return record.cve_id
    return record.id


def _ensure_provenance(record: CanonicalRecord, context: SourceContext) -> CanonicalRecord:
    if not hasattr(record, "provenance"):
        return record
    if record.provenance:
        return record
    provenance = Provenance(
        source=context.source,
        fetched_at=context.fetched_at,
        url=context.url,
        license=context.license,
        field="*",
        confidence=context.confidence,  # type: ignore[arg-type]
    )
    return record.model_copy(update={"provenance": [provenance]})


def _field_provenance(record: CanonicalRecord, field_name: str) -> list[Provenance]:
    provenance = getattr(record, "provenance", [])
    exact = [item for item in provenance if item.field == field_name]
    if exact:
        return exact
    return [item for item in provenance if item.field == "*"]


def _merge_provenance(old: CanonicalRecord, new: CanonicalRecord) -> list[Provenance]:
    result: list[Provenance] = []
    seen: set[tuple[object, ...]] = set()
    for item in [*getattr(old, "provenance", []), *getattr(new, "provenance", [])]:
        key = (
            item.source,
            item.fetched_at,
            item.url,
            item.license,
            item.field,
            item.confidence,
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _choose(old: _Candidate, new: _Candidate) -> _Candidate:
    old_key = (old.precedence, old.fetched_at, old.source)
    new_key = (new.precedence, new.fetched_at, new.source)
    return new if new_key >= old_key else old


def _winner_candidate(
    old: _Candidate,
    new: _Candidate,
    old_value: Any,
    new_value: Any,
) -> _Candidate | None:
    if _is_missing(old_value):
        return new
    if _is_missing(new_value):
        return old
    return _choose(old, new)


def _catalog_winner(
    old: _Candidate,
    new: _Candidate,
    old_value: Any,
    new_value: Any,
) -> _Candidate:
    if (
        not _is_missing(old_value)
        and not _is_missing(new_value)
        and _json_value(old_value) == _json_value(new_value)
        and old.source == new.source
    ):
        return old
    return _winner_candidate(old, new, old_value, new_value) or old


def _append_catalog_list_provenance(
    existing_record: CanonicalRecord,
    target: list[Provenance],
    field_name: str,
    merged_value: list[Any],
    old_value: list[Any],
    new_value: list[Any],
    old: _Candidate,
    new: _Candidate,
) -> None:
    """Attribute additive catalog list members to the source that supplied them."""
    old_items = set(old_value)
    new_items = set(new_value)
    new_contributed = bool(new_items - old_items)
    prior = [
        item
        for item in getattr(existing_record, "provenance", [])
        if item.field == field_name or item.field.startswith(f"{field_name}:")
    ]
    for evidence in prior:
        _append_catalog_field_evidence(target, field_name, evidence)
    old_evidence = old.provenance
    if not prior and old_evidence is not None:
        _append_catalog_field_evidence(target, field_name, old_evidence)
    if new_contributed and new.provenance is not None:
        _append_catalog_field_evidence(target, field_name, new.provenance)


def _append_catalog_field_evidence(
    target: list[Provenance], field_name: str, source: Provenance
) -> None:
    if any(item.field == field_name and item.source == source.source for item in target):
        return
    target.append(source.model_copy(update={"field": field_name}))


def _append_field_provenance(
    target: list[Provenance], source: Provenance | None, field_name: str
) -> None:
    if source is None or source.field == "__inferred__":
        return
    target[:] = [
        item for item in target if item.field != field_name or item.source == source.source
    ]
    item = source.model_copy(update={"field": field_name})
    if item not in target:
        target.append(item)


def _is_missing(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    # Round-tripping through JSON gives deterministic primitive values for
    # dates and datetimes while keeping conflict rows JSON serializable.
    try:
        return json.loads(json.dumps(value, default=str, sort_keys=True))
    except TypeError:
        return str(value)


def _union_scalars(old: list[Any], new: list[Any], new_first: bool) -> list[Any]:
    result: list[Any] = []
    seen: set[Any] = set()
    for value in ([*new, *old] if new_first else [*old, *new]):
        try:
            marker = value
            if marker in seen:
                continue
            seen.add(marker)
        except TypeError:
            marker = json.dumps(value, sort_keys=True, default=str)
            if marker in seen:
                continue
            seen.add(marker)
        result.append(value)
    return result


def _group_ranges(
    ranges: list[Any], record: _Candidate, field_name: str
) -> dict[tuple[str, str] | None, list[Any]]:
    groups: dict[tuple[str, str] | None, list[Any]] = {}
    for item in ranges:
        groups.setdefault(_range_scope(item, record, field_name), []).append(item)
    return groups


def _range_scope(
    item: Any, record: _Candidate, field_name: str = "ranges"
) -> tuple[str, str] | None:
    provenance = getattr(item, "provenance", [])
    if provenance:
        selected = max(
            provenance,
            key=lambda value: (value.fetched_at, value.source, value.url),
        )
        if field_name == "closed_scopes":
            return selected.source, "__publisher__"
        if selected.source == "cvelistv5":
            # CVE List records are complete advisory snapshots. Archive and
            # raw/delta URLs are transport variants of one publisher slice.
            return selected.source, "__publisher__"
        return selected.source, _canonical_url_scope(selected.url)
    if item is None and record.provenance is not None:
        if field_name == "closed_scopes":
            return record.source, "__publisher__"
        if record.source == "cvelistv5":
            return record.source, "__publisher__"
        return record.source, _canonical_url_scope(record.provenance.url)
    return None


def _range_source(item: Any, record: _Candidate) -> str:
    scope = _range_scope(item, record)
    return scope[0] if scope is not None else record.source


def _range_precedence(item: Any, record: _Candidate, merger: Merger) -> int:
    return merger._precedence(_range_source(item, record))


def _range_order_key(item: Any, record: _Candidate, merger: Merger) -> tuple[int, datetime, str]:
    provenance = getattr(item, "provenance", [])
    fetched_at = max((value.fetched_at for value in provenance), default=record.fetched_at)
    source = _range_source(item, record)
    return merger._precedence(source), fetched_at, source


def _candidate_order_key(candidate: _Candidate, merger: Merger) -> tuple[int, datetime, str]:
    return merger._precedence(candidate.source), candidate.fetched_at, candidate.source


def _range_conflict(
    *,
    record_type: str,
    record_id: str,
    scope: tuple[str, str],
    field_name: str,
    kept: list[Any],
    incoming: list[Any],
    kept_source: str,
    incoming_source: str,
    kept_precedence: int,
    incoming_precedence: int,
    detected_at: datetime,
) -> Conflict:
    return Conflict(
        record_type=record_type,
        record_id=record_id,
        field=f"{field_name}[{scope[0]}:{scope[1]}]",
        kept_value=_json_value(kept),
        incoming_value=_json_value(incoming),
        kept_source=kept_source,
        incoming_source=incoming_source,
        kept_precedence=kept_precedence,
        incoming_precedence=incoming_precedence,
        detected_at=detected_at,
        losing_source=incoming_source,
        losing_value=_json_value(incoming),
    )


def _canonical_url_scope(url: str) -> str:
    """Normalize query ordering so a corrected request maps to one slice."""

    parsed = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _is_authoritative_empty(candidate: _Candidate) -> bool:
    return candidate.explicit_field and candidate.provenance is not None and candidate.provenance.field in {
        "supported_platforms_by_release",
        "withdrawal",
    }


def _has_generated_field_marker(record: CanonicalRecord, selected: Provenance) -> bool:
    return any(
        item.field == "*"
        and item.source == selected.source
        and item.fetched_at == selected.fetched_at
        and item.url == selected.url
        and item.license == selected.license
        for item in getattr(record, "provenance", [])
    )


def _range_key(item: Any) -> str:
    if isinstance(item, BaseModel):
        payload = item.model_dump(mode="json")
        payload.pop("provenance", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))


def _range_semantic_key(item: Any) -> str:
    if isinstance(item, BaseModel):
        payload = item.model_dump(mode="json")
        for field in ("provenance", "status", "fixed_versions", "default_status"):
            payload.pop(field, None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))


def _range_fact_key(item: Any) -> str:
    if isinstance(item, BaseModel):
        payload = item.model_dump(mode="json")
        payload.pop("provenance", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))

