"""Offline dataset export loading for the standalone matching library.

The export format is deliberately small and append-only.  It is the format
published by :mod:`osak.ingest.export`: each JSONL record is an envelope with
``record_type`` and a ``record`` object.  A leading ``metadata`` record carries
dataset-wide source status.  The loader validates every canonical record before
returning a Dataset, and it never performs network or database I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from osak.core.models import (
    Advisory,
    Dataset,
    Enrichment,
    EoLRecord,
    HardwareModel,
    Product,
    SourceAvailability,
    Vendor,
)


class DatasetLoadError(ValueError):
    """Raised when an offline JSONL export cannot be loaded safely."""


class DatasetChecksumError(DatasetLoadError):
    """Raised when the export bytes do not match the expected SHA-256 digest."""


_RECORD_TYPES: Final[dict[str, type[Any]]] = {
    "vendor": Vendor,
    "product": Product,
    "hardware_model": HardwareModel,
    "advisory": Advisory,
    "enrichment": Enrichment,
    "eol": EoLRecord,
}


def _check_checksum(actual: str, checksum: str | None) -> None:
    if checksum is None:
        return
    expected = checksum.removeprefix("sha256:").lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise DatasetChecksumError("checksum must be a SHA-256 hexadecimal digest")
    if not hmac.compare_digest(actual, expected):
        raise DatasetChecksumError(
            f"dataset checksum mismatch: expected {expected}, got {actual}"
        )


def _record_data(row: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    raw_type = row.get("record_type")
    if not isinstance(raw_type, str) or not raw_type:
        raise DatasetLoadError("dataset record must contain a non-empty string 'record_type'")
    record_type = raw_type.casefold()
    model = _RECORD_TYPES.get(record_type)
    if model is None and record_type != "metadata":
        raise DatasetLoadError(f"unsupported dataset record type: {raw_type}")
    raw_data = row.get("record")
    if not isinstance(raw_data, Mapping):
        raise DatasetLoadError(f"dataset {record_type} record must contain an object 'record'")
    return record_type, raw_data


def _load_line(line: bytes, line_number: int) -> tuple[str, Mapping[str, Any]]:
    try:
        value = json.loads(line)
    except UnicodeDecodeError as exc:
        raise DatasetLoadError(f"invalid UTF-8 on dataset line {line_number}") from exc
    except json.JSONDecodeError as exc:
        raise DatasetLoadError(f"invalid JSON on dataset line {line_number}: {exc.msg}") from exc
    if not isinstance(value, Mapping):
        raise DatasetLoadError(f"dataset line {line_number} must be a JSON object")
    return _record_data(value)


def load_dataset_jsonl(
    path: str | Path,
    checksum: str | None = None,
) -> Dataset:
    """Load and validate a checksummed JSONL dataset export.

    ``checksum`` is the SHA-256 digest of the exact JSONL file bytes.  Records
    are parsed as a stream while the digest is calculated, so the loader does
    not hold a second copy of a large export in memory.
    """

    expected_checksum = checksum
    if expected_checksum is not None:
        expected_checksum = expected_checksum.removeprefix("sha256:").lower()
        if len(expected_checksum) != 64 or any(
            character not in "0123456789abcdef" for character in expected_checksum
        ):
            raise DatasetChecksumError("checksum must be a SHA-256 hexadecimal digest")
    export_path = Path(path)

    records: dict[str, list[Any]] = {
        "vendor": [],
        "product": [],
        "model": [],
        "advisory": [],
        "enrichment": [],
        "eol": [],
    }
    unavailable_sources: list[str] = []
    source_statuses: dict[str, SourceAvailability] = {}
    digest = hashlib.sha256()
    try:
        stream = export_path.open("rb")
    except OSError as exc:
        raise DatasetLoadError(f"could not read dataset export {export_path}: {exc}") from exc
    with stream:
        for line_number, line in enumerate(stream, start=1):
            digest.update(line)
            if not line.strip():
                continue
            record_type, record_data = _load_line(line, line_number)
            if record_type == "metadata":
                raw_statuses = record_data.get("source_statuses", [])
                if not isinstance(raw_statuses, list):
                    raise DatasetLoadError(
                        f"dataset metadata on line {line_number} has invalid source_statuses"
                    )
                for status in raw_statuses:
                    if not isinstance(status, Mapping):
                        raise DatasetLoadError(
                            f"dataset metadata on line {line_number} has invalid source status"
                        )
                    source_id = status.get("source_id")
                    state = status.get("state", status.get("status", "unknown"))
                    if not isinstance(source_id, str) or not source_id:
                        raise DatasetLoadError(
                            f"dataset metadata on line {line_number} has invalid source_id"
                        )
                    if not isinstance(state, str) or not state:
                        raise DatasetLoadError(
                            f"dataset metadata on line {line_number} has invalid source state"
                        )
                    kind = status.get("kind")
                    if kind is not None and kind not in {"advisory", "enrichment", "eol"}:
                        kind = None
                    vendor_scope = status.get("vendor_scope", [])
                    if not isinstance(vendor_scope, list) or not all(
                        isinstance(vendor, str) and vendor for vendor in vendor_scope
                    ):
                        raise DatasetLoadError(
                            f"dataset metadata on line {line_number} has invalid vendor_scope"
                        )
                    operator_excluded = bool(
                        status.get("operator_excluded", False)
                        or state in {"disabled", "unapproved"}
                        or status.get("allowed") is False
                    )
                    source_statuses[source_id] = SourceAvailability(
                        source_id=source_id,
                        state=state,
                        kind=kind,
                        vendor_scope=vendor_scope,
                        operator_excluded=operator_excluded,
                    )
                    if state != "healthy":
                        unavailable_sources.append(source_id)
                raw_unavailable = record_data.get("unavailable_sources", [])
                if not isinstance(raw_unavailable, list) or not all(
                    isinstance(source, str) and source for source in raw_unavailable
                ):
                    raise DatasetLoadError(
                        f"dataset metadata on line {line_number} has invalid unavailable_sources"
                    )
                unavailable_sources.extend(raw_unavailable)
                continue
            model = _RECORD_TYPES[record_type]
            try:
                destination = "model" if record_type == "hardware_model" else record_type
                records[destination].append(model.model_validate(record_data))
            except ValidationError as exc:
                raise DatasetLoadError(
                    f"invalid {record_type} record on dataset line {line_number}: {exc}"
                ) from exc

    _check_checksum(digest.hexdigest(), expected_checksum)

    for source_id in unavailable_sources:
        source_statuses.setdefault(
            source_id,
            SourceAvailability(source_id=source_id, state="unknown"),
        )
    return Dataset(
        vendors=records["vendor"],
        products=records["product"],
        models=records["model"],
        advisories=records["advisory"],
        enrichments=records["enrichment"],
        eol=records["eol"],
        unavailable_sources=list(dict.fromkeys(unavailable_sources)),
        source_statuses=list(source_statuses.values()),
    )


def load_dataset(
    path: str | Path,
    checksum: str | None = None,
) -> Dataset:
    """Short alias for :func:`load_dataset_jsonl`."""

    return load_dataset_jsonl(path, checksum)
