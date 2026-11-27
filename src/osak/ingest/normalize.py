"""Validation and provenance attachment for connector output."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

from pydantic import TypeAdapter, ValidationError

from osak.connectors.base import Connector, RawDocument
from osak.core.models import CanonicalRecord, Provenance
from osak.ingest.merge import SourceContext


class NormalizationError(ValueError):
    """A connector returned data that cannot be represented canonically."""


_CANONICAL_ADAPTER: Any = TypeAdapter(CanonicalRecord)  # type: ignore[arg-type]


def normalize_document(
    connector: Connector,
    raw: RawDocument,
    *,
    context: SourceContext | None = None,
) -> Iterator[CanonicalRecord]:
    """Yield validated canonical records without buffering a source corpus."""

    if context is None:
        context = SourceContext(
            source=connector.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license=connector.license.name,
        )
    try:
        normalized = connector.normalize(raw)
        for candidate in normalized:
            record = _validate(candidate)
            if hasattr(record, "provenance") and not record.provenance:
                record = record.model_copy(
                    update={
                        "provenance": [
                            Provenance(
                                source=context.source,
                                fetched_at=context.fetched_at,
                                url=context.url,
                                license=context.license,
                                field="*",
                                confidence=context.confidence,  # type: ignore[arg-type]
                            )
                        ]
                    }
                )
            yield record
    except NormalizationError:
        raise
    except Exception as exc:
        raise NormalizationError(f"{connector.id} failed to normalize {raw.url}: {exc}") from exc


def _validate(candidate: Any) -> CanonicalRecord:
    try:
        return cast(CanonicalRecord, _CANONICAL_ADAPTER.validate_python(candidate))
    except ValidationError as exc:
        raise NormalizationError(f"connector emitted invalid canonical record: {exc}") from exc

