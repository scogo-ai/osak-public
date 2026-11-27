"""Persistence contracts and an in-memory implementation for ingestion tests.

The production core may implement the same protocol with SQLAlchemy/PostgreSQL.
Keeping the methods small makes the worker's transactional boundary explicit:
raw documents and canonical facts are idempotent, while a checkpoint advances
only after a successful poll.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Protocol

from osak.connectors.base import RawDocument
from osak.core.models import Advisory, CanonicalRecord, Product
from osak.ingest.merge import Merger, MergeResult, SourceContext
from osak.ingest.types import Checkpoint, Conflict, RawBlob, SourceStatus


class IngestRepository(Protocol):
    """Persistence surface required by :class:`~osak.ingest.worker.IngestWorker`.

    Implementations should make ``commit_checkpoint`` transactional with the
    source status update.  The worker intentionally does not update a cursor
    before that call.
    """

    def get_checkpoint(self, source_id: str) -> Checkpoint | None: ...

    def commit_checkpoint(self, checkpoint: Checkpoint) -> None: ...

    def put_raw(self, source_id: str, raw: RawDocument) -> RawBlob: ...

    def has_advisory(self, advisory_id: str) -> bool: ...

    def advisory_cve_ids(self, vendors: list[str]) -> set[str]: ...

    def merge_record(self, record: CanonicalRecord, context: SourceContext) -> MergeResult: ...

    def append_conflicts(self, conflicts: Iterable[Conflict]) -> None: ...

    def set_source_status(self, status: SourceStatus) -> None: ...

    def get_source_status(self, source_id: str) -> SourceStatus: ...

    def source_status_at(self, source_id: str, now: datetime) -> SourceStatus: ...

    def iter_records(self) -> Iterable[CanonicalRecord]: ...

    def list_source_status(self, now: datetime | None = None) -> list[SourceStatus]: ...


class InMemoryRepository:
    """Thread-safe repository useful for unit tests and local development."""

    def __init__(self, merger: Merger | None = None) -> None:
        self.merger = merger or Merger()
        self.raw: dict[str, tuple[RawBlob, RawDocument]] = {}
        self.records: dict[tuple[str, str], CanonicalRecord] = {}
        self.conflicts: list[Conflict] = []
        self.checkpoints: dict[str, Checkpoint] = {}
        self.statuses: dict[str, SourceStatus] = {}
        self.exports: list[object] = []
        self._lock = threading.RLock()

    def get_checkpoint(self, source_id: str) -> Checkpoint | None:
        with self._lock:
            value = self.checkpoints.get(source_id)
            return value.model_copy(deep=True) if value is not None else None

    def commit_checkpoint(self, checkpoint: Checkpoint) -> None:
        with self._lock:
            old = self.checkpoints.get(checkpoint.source_id)
            if old is not None and checkpoint.generation < old.generation:
                raise ValueError("checkpoint generation cannot move backwards")
            self.checkpoints[checkpoint.source_id] = checkpoint.model_copy(deep=True)

    def commit_poll(self, checkpoint: Checkpoint, status: SourceStatus) -> None:
        """Atomically publish a successful checkpoint and its source status."""

        with self._lock:
            old = self.checkpoints.get(checkpoint.source_id)
            if old is not None and checkpoint.generation < old.generation:
                raise ValueError("checkpoint generation cannot move backwards")
            self.checkpoints[checkpoint.source_id] = checkpoint.model_copy(deep=True)
            self.statuses[status.source_id] = status.model_copy(deep=True)

    def put_raw(self, source_id: str, raw: RawDocument) -> RawBlob:
        import hashlib

        content_hash = hashlib.sha256(raw.content).hexdigest()
        blob = RawBlob(
            content_hash=content_hash,
            source_id=source_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            media_type=raw.media_type,
            byte_size=len(raw.content),
        )
        with self._lock:
            old = self.raw.get(content_hash)
            if old is not None and old[1].content != raw.content:
                raise ValueError(f"raw document {content_hash} is immutable and was modified")
            if old is None:
                self.raw[content_hash] = (blob, raw)
            return blob

    def get_raw(self, content_hash: str) -> RawDocument:
        with self._lock:
            try:
                return self.raw[content_hash][1]
            except KeyError as exc:
                raise FileNotFoundError(content_hash) from exc

    def has_advisory(self, advisory_id: str) -> bool:
        with self._lock:
            return ("advisory", advisory_id) in self.records or any(
                isinstance(item, Advisory) and advisory_id in item.cves
                for item in self.records.values()
            )

    def advisory_cve_ids(self, vendors: list[str]) -> set[str]:
        with self._lock:
            products = {
                item.id for item in self.records.values()
                if isinstance(item, Product) and item.vendor_id in vendors
            }
            return {
                cve
                for item in self.records.values()
                if isinstance(item, Advisory)
                and (item.vendor_id in vendors or any(r.product_id in products for r in item.ranges))
                for cve in item.cves
            }

    def merge_record(self, record: CanonicalRecord, context: SourceContext) -> MergeResult:
        key = (_record_kind(record), _record_id(record))
        with self._lock:
            result: MergeResult = self.merger.merge(self.records.get(key), record, context)
            self.records[key] = result.record.model_copy(deep=True)
            return result

    def append_conflicts(self, conflicts: Iterable[Conflict]) -> None:
        with self._lock:
            existing = {
                (
                    item.record_type,
                    item.record_id,
                    item.field,
                    item.kept_source,
                    item.incoming_source,
                    item.losing_source,
                    item.kept_value.__repr__(),
                    item.incoming_value.__repr__(),
                )
                for item in self.conflicts
            }
            for conflict in conflicts:
                key = (
                    conflict.record_type,
                    conflict.record_id,
                    conflict.field,
                    conflict.kept_source,
                    conflict.incoming_source,
                    conflict.losing_source,
                    conflict.kept_value.__repr__(),
                    conflict.incoming_value.__repr__(),
                )
                if key not in existing:
                    self.conflicts.append(conflict)
                    existing.add(key)

    def set_source_status(self, status: SourceStatus) -> None:
        with self._lock:
            self.statuses[status.source_id] = status.model_copy(deep=True)

    def get_source_status(self, source_id: str) -> SourceStatus:
        with self._lock:
            try:
                return self.statuses[source_id].model_copy(deep=True)
            except KeyError as exc:
                raise KeyError(f"unknown source status {source_id!r}") from exc

    def source_status_at(self, source_id: str, now: datetime) -> SourceStatus:
        return self.get_source_status(source_id).at(now)

    def iter_records(self) -> Iterable[CanonicalRecord]:
        with self._lock:
            snapshot = [record.model_copy(deep=True) for record in self.records.values()]
        yield from sorted(snapshot, key=lambda item: (_record_kind(item), _record_id(item)))

    def list_source_status(self, now: datetime | None = None) -> list[SourceStatus]:
        current = now or datetime.now(UTC)
        with self._lock:
            result = [status.at(current) for status in self.statuses.values()]
        return sorted(result, key=lambda item: item.source_id)

    def append_export_manifest(self, manifest: object) -> None:
        with self._lock:
            self.exports.append(manifest)


def _record_kind(record: CanonicalRecord) -> str:
    from osak.core.models import Advisory, Enrichment, EoLRecord, HardwareModel, Product, Vendor

    return {
        Vendor: "vendor",
        Product: "product",
        HardwareModel: "hardware_model",
        Advisory: "advisory",
        Enrichment: "enrichment",
        EoLRecord: "eol",
    }[type(record)]


def _record_id(record: CanonicalRecord) -> str:
    from osak.core.models import Enrichment

    return record.cve_id if isinstance(record, Enrichment) else record.id

