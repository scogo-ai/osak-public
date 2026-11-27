"""Streaming, atomic JSONL publication for offline matching."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from osak.core.models import CanonicalRecord
from osak.ingest.types import ExportManifest


class Exporter(Protocol):
    """Minimal export surface used by the nightly scheduler."""

    def export(self, *, generated_at: datetime | None = None) -> ExportManifest: ...


class DatasetExporter:
    """Write only normalized canonical records to a checksummed JSONL file.

    The repository iterator is consumed exactly once.  This matters for the
    CVE corpus, which can be too large to materialize as a ``Dataset`` in
    memory.  A temporary file and atomic ``os.replace`` ensure a failed export
    never replaces the last published snapshot.
    """

    def __init__(
        self,
        repository: Any,
        output_dir: str | os.PathLike[str],
        *,
        notice_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        self.repository = repository
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.latest_manifest_path = self.output_dir / "latest.json"
        self.notice_dir = Path(notice_dir) if notice_dir is not None else Path(__file__).with_name("notices")

    def export(self, *, generated_at: datetime | None = None) -> ExportManifest:
        when = generated_at or datetime.now(UTC)
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        else:
            when = when.astimezone(UTC)
        digest = hashlib.sha256()
        counts: Counter[str] = Counter()
        source_ids: set[str] = set()
        source_statuses = _source_statuses(self.repository, when)
        license_notices = _license_notices(source_statuses, self.notice_dir)
        unavailable_sources = sorted(
            str(item["source_id"]) for item in source_statuses if item.get("state") != "healthy"
        )
        byte_count = 0
        record_count = 0
        fd, temp_name = tempfile.mkstemp(dir=self.output_dir, suffix=".partial")
        temporary = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                metadata = {
                    "record_type": "metadata",
                    "record": {
                        "schema_version": "1",
                        "generated_at": when.isoformat(),
                        "license_notices": license_notices,
                        "source_statuses": source_statuses,
                        "unavailable_sources": unavailable_sources,
                    },
                }
                metadata_line = json.dumps(
                    metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8") + b"\n"
                handle.write(metadata_line)
                digest.update(metadata_line)
                byte_count += len(metadata_line)
                for record in self.repository.iter_records():
                    record_type = record_type_for(record)
                    payload = record.model_dump(mode="json")
                    line = json.dumps(
                        {"record_type": record_type, "record": payload},
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8") + b"\n"
                    handle.write(line)
                    digest.update(line)
                    byte_count += len(line)
                    record_count += 1
                    counts[record_type] += 1
                    source_ids.update(item.source for item in getattr(record, "provenance", []))
                source_ids.update(item["source_id"] for item in source_statuses)
                handle.flush()
                os.fsync(handle.fileno())
            destination = self.output_dir / f"dataset-{digest.hexdigest()}.jsonl"
            os.replace(temporary, destination)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

        manifest = ExportManifest(
            generated_at=when,
            dataset_path=destination.name,
            download_url=f"/api/v1/datasets/files/{destination.name}",
            manifest_path=self.latest_manifest_path.name,
            sha256=digest.hexdigest(),
            byte_count=byte_count,
            record_count=record_count,
            record_types=dict(sorted(counts.items())),
            source_ids=sorted(source_ids),
            license_notices=license_notices,
            source_statuses=source_statuses,
            unavailable_sources=unavailable_sources,
        )
        manifest_bytes = json.dumps(
            manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        _atomic_write(self.latest_manifest_path, manifest_bytes)
        append_manifest = getattr(self.repository, "append_export_manifest", None)
        if append_manifest is not None:
            append_manifest(manifest)
        return manifest


class NightlyExportScheduler:
    """Run an export once per UTC calendar day after a configured hour."""

    def __init__(
        self,
        exporter: Exporter,
        *,
        hour_utc: int = 2,
        clock: Any | None = None,
    ) -> None:
        if not 0 <= hour_utc <= 23:
            raise ValueError("hour_utc must be between 0 and 23")
        self.exporter = exporter
        self.hour_utc = hour_utc
        self.clock = clock or (lambda: datetime.now(UTC))
        self._last_export_date: date | None = None

    def run_once(self, *, now: datetime | None = None) -> ExportManifest | None:
        current = now or self.clock()
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        else:
            current = current.astimezone(UTC)
        if current.hour < self.hour_utc or self._last_export_date == current.date():
            return None
        manifest = self.exporter.export(generated_at=current)
        self._last_export_date = current.date()
        return manifest


class NightlyMaintenance:
    """Coordinate the nightly dataset export and account metadata rollup."""

    def __init__(
        self,
        exporter: NightlyExportScheduler,
        *,
        rollup: Callable[[datetime], object] | None = None,
    ) -> None:
        self.exporter = exporter
        self.rollup = rollup

    def run_once(self, *, now: datetime | None = None) -> ExportManifest | None:
        manifest = self.exporter.run_once(now=now)
        if manifest is not None and self.rollup is not None:
            self.rollup(manifest.generated_at)
        return manifest


def record_type_for(record: CanonicalRecord) -> str:
    from osak.core.models import Advisory, Enrichment, EoLRecord, HardwareModel, Product, Vendor

    mapping = {
        Vendor: "vendor",
        Product: "product",
        HardwareModel: "hardware_model",
        Advisory: "advisory",
        Enrichment: "enrichment",
        EoLRecord: "eol",
    }
    try:
        return mapping[type(record)]
    except KeyError as exc:
        raise TypeError(f"unsupported canonical record type: {type(record).__name__}") from exc


def read_jsonl_dataset(path: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
    """Read an export lazily, validating its envelope but not buffering it."""

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid dataset JSONL at line {line_number}") from exc
            if not isinstance(item, dict) or not isinstance(item.get("record_type"), str):
                raise TypeError(f"invalid dataset envelope at line {line_number}")
            if not isinstance(item.get("record"), dict):
                raise TypeError(f"invalid dataset record at line {line_number}")
            yield item


def _source_statuses(repository: Any, generated_at: datetime) -> list[dict[str, Any]]:
    list_status = getattr(repository, "list_source_status", None)
    if list_status is None:
        return []
    return [item.model_dump(mode="json") for item in list_status(generated_at)]


def _license_notices(
    statuses: list[dict[str, Any]], notice_dir: Path | None = None
) -> list[dict[str, str]]:
    notices: list[dict[str, str]] = []
    for status in statuses:
        source_id = str(status.get("source_id", ""))
        notice = {
            "source_id": source_id,
            "license": str(status.get("license_name", "")),
            "license_url": str(status.get("license_url", "")),
            "attribution": str(status.get("attribution", "")),
            "redistribution": str(status.get("redistribution", "review")),
        }
        if notice not in notices:
            notices.append(notice)
    if notice_dir is not None and notice_dir.is_dir():
        for path in sorted(notice_dir.glob("*.txt")):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            notices.append(
                {
                    "source_id": f"notice:{path.stem}",
                    "license": "source terms notice",
                    "license_url": "",
                    "attribution": path.name,
                    "redistribution": "notice",
                    "notice_text": text,
                }
            )
    return notices


def _atomic_write(path: Path, content: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

