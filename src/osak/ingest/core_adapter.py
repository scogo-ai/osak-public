"""Adapter from the ingest repository protocol to ``osak.core.repository``.

Core intentionally exposes small SQLAlchemy write/query helpers rather than an
ingest-specific service.  This adapter supplies the transaction boundary the
worker needs while keeping the worker independent of SQLAlchemy.  The caller
owns ``session_scope`` (or another transaction context); ``commit_poll`` only
flushes changes, so raw facts, canonical records, conflicts and the checkpoint
commit together.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session, selectinload

from osak.connectors.base import RawDocument
from osak.core import repository as core
from osak.core.db_models import (
    AdvisoryCVERow,
    AdvisoryRow,
    AffectedRangeRow,
    EnrichmentRow,
    EoLRecordRow,
    HardwareModelRow,
    ProductRow,
    RawDocumentRow,
    VendorRow,
)
from osak.core.models import (
    Advisory,
    CanonicalRecord,
    Enrichment,
    EoLRecord,
    HardwareModel,
    Product,
    Vendor,
)
from osak.ingest.merge import Merger, MergeResult, SourceContext
from osak.ingest.types import Checkpoint, Conflict, RawBlob, SourceStatus


class CoreIngestRepository:
    """Use core's SQLAlchemy repository as an ingest persistence backend."""

    def __init__(self, session: Session, *, merger: Merger | None = None) -> None:
        self.session = session
        self.merger = merger or Merger()

    def get_checkpoint(self, source_id: str) -> Checkpoint | None:
        state = core.get_source_sync_state(self.session, source_id)
        if state is None or state.last_success_at is None:
            return None
        cursor: datetime | str | None = _cursor_value(state.cursor) if state.cursor else None
        metadata = cast(dict[str, Any], state.metadata)
        generation = int(metadata.get("generation", 0))
        return Checkpoint(
            source_id=source_id,
            cursor=cursor,
            last_success_at=state.last_success_at,
            generation=generation,
        )

    def commit_checkpoint(self, checkpoint: Checkpoint) -> None:
        old = self.get_checkpoint(checkpoint.source_id)
        if old is not None and checkpoint.generation < old.generation:
            raise ValueError("checkpoint generation cannot move backwards")
        self._save_sync_state(
            checkpoint.source_id,
            status="success",
            last_success_at=checkpoint.last_success_at,
            cursor=_cursor_text(checkpoint.cursor),
            metadata={"generation": checkpoint.generation},
        )

    def commit_poll(self, checkpoint: Checkpoint, status: SourceStatus) -> None:
        """Persist success state and status in the caller's transaction."""

        old = self.get_checkpoint(checkpoint.source_id)
        if old is not None and checkpoint.generation < old.generation:
            raise ValueError("checkpoint generation cannot move backwards")
        self._save_sync_state(
            checkpoint.source_id,
            status="success",
            last_started_at=status.last_attempt_at,
            last_attempt_at=status.last_attempt_at,
            last_success_at=checkpoint.last_success_at,
            cursor=_cursor_text(checkpoint.cursor),
            records_seen=status.documents_seen,
            records_written=status.records_seen,
            metadata=_status_metadata(status, generation=checkpoint.generation),
        )

    def put_raw(self, source_id: str, raw: RawDocument) -> RawBlob:
        self._lock_raw(raw)
        row = core.store_raw_document(self.session, raw, source_id=source_id)
        return RawBlob(
            content_hash=row.content_hash,
            source_id=source_id,
            url=row.url,
            fetched_at=_aware(row.fetched_at),
            media_type=row.media_type,
            byte_size=len(row.content),
        )

    def has_advisory(self, advisory_id: str) -> bool:
        if self.session.get(AdvisoryRow, advisory_id) is not None:
            return True
        return self.session.scalar(
            select(AdvisoryCVERow.cve_id).where(AdvisoryCVERow.cve_id == advisory_id).limit(1)
        ) is not None

    def advisory_cve_ids(self, vendors: list[str]) -> set[str]:
        query = (
            select(AdvisoryCVERow.cve_id)
            .join(AdvisoryRow, AdvisoryCVERow.advisory_id == AdvisoryRow.id)
            .outerjoin(AffectedRangeRow, AffectedRangeRow.advisory_id == AdvisoryRow.id)
            .outerjoin(ProductRow, ProductRow.id == AffectedRangeRow.product_id)
            .where(or_(AdvisoryRow.vendor_id.in_(vendors), ProductRow.vendor_id.in_(vendors)))
            .distinct()
        )
        return set(self.session.scalars(query))

    def merge_record(self, record: CanonicalRecord, context: SourceContext) -> MergeResult:
        self._lock_record(record)
        existing = self._get_record(record)
        result = self.merger.merge(existing, record, context)
        if result.changed:
            core.save_canonical_record(
                self.session,
                result.record,
                source_id=context.source,
                previous=existing,
                changed=True,
            )
        return result

    def append_conflicts(self, conflicts: Iterable[Conflict]) -> None:
        for conflict in conflicts:
            core.record_conflict(
                self.session,
                record_type=conflict.record_type,
                record_id=conflict.record_id,
                field=conflict.field,
                winner_source=conflict.kept_source,
                loser_source=conflict.losing_source or conflict.incoming_source,
                winning_value=conflict.kept_value,
                losing_value=conflict.losing_value,
                detected_at=conflict.detected_at,
            )

    def set_source_status(self, status: SourceStatus) -> None:
        core_status = {
            "healthy": "success",
            "stale": "failed",
            "unavailable": "failed",
            "never_synced": "idle",
            "running": "running",
            "disabled": "disabled",
            "unapproved": "disabled",
        }[status.state]
        previous = core.get_source_sync_state(self.session, status.source_id)
        self._save_sync_state(
            status.source_id,
            status=core_status,
            last_started_at=status.last_attempt_at if status.allowed else None,
            last_attempt_at=status.last_attempt_at,
            last_success_at=status.last_success_at,
            cursor=previous.cursor if previous else None,
            error=None if status.state in {"healthy", "never_synced", "running"} else status.detail,
            records_seen=status.documents_seen,
            records_written=status.records_seen,
            metadata=_status_metadata(
                status,
                generation=int(
                    cast(dict[str, Any], previous.metadata if previous else {}).get("generation", 0)
                ),
            ),
        )

    def get_source_status(self, source_id: str) -> SourceStatus:
        state = core.get_source_sync_state(self.session, source_id)
        if state is None:
            raise KeyError(source_id)
        metadata = cast(dict[str, Any], state.metadata)
        policy_state = metadata.get("policy_state")
        status = {
            "success": "healthy",
            "failed": "unavailable",
            "idle": "never_synced",
            "running": "running",
            "disabled": policy_state or "disabled",
        }.get(state.status, "unavailable")
        schedule = int(metadata.get("schedule_seconds", 3600))
        return SourceStatus(
            source_id=source_id,
            enabled=bool(metadata.get("enabled", state.status != "disabled")),
            allowed=bool(metadata.get("allowed", state.status != "disabled")),
            state=status,  # type: ignore[arg-type]
            detail=str(metadata.get("detail", state.error or "")),
            schedule_seconds=max(schedule, 1),
            stale_after_seconds=max(int(metadata.get("stale_after_seconds", schedule * 3)), 1),
            last_attempt_at=state.last_attempt_at,
            last_success_at=state.last_success_at,
            next_due_at=metadata.get("next_due_at"),
            updated_at=(state.last_success_at if state.status == "success" else state.last_attempt_at)
            or datetime.now(UTC),
            consecutive_failures=int(metadata.get("consecutive_failures", 0)),
            documents_seen=state.records_seen,
            records_seen=state.records_written,
            license_name=str(metadata.get("license_name", "")),
            license_url=str(metadata.get("license_url", "")),
            attribution=str(metadata.get("attribution", "")),
            redistribution=str(metadata.get("redistribution", "review")),
            kind=metadata.get("kind"),
            vendor_scope=list(metadata.get("vendor_scope", [])),
            operator_excluded=bool(
                metadata.get("operator_excluded", False)
                or metadata.get("policy_state") in {"disabled", "unapproved"}
                or not bool(metadata.get("allowed", True))
            ),
        )

    def source_status_at(self, source_id: str, now: datetime) -> SourceStatus:
        return self.get_source_status(source_id).at(now)

    def list_source_status(self, now: datetime | None = None) -> list[SourceStatus]:
        current = now or datetime.now(UTC)
        return [
            status.at(current)
            for status in (
                self.get_source_status(state.source_id)
                for state in core.list_source_sync_states(self.session)
            )
        ]

    def iter_records(self) -> Iterator[CanonicalRecord]:
        """Stream canonical rows instead of materializing a Dataset."""

        for vendor_row in self.session.scalars(select(VendorRow).order_by(VendorRow.id)).yield_per(
            256
        ):
            yield core._vendor_from_row(vendor_row)
        for product_row in self.session.scalars(
            select(ProductRow).order_by(ProductRow.id)
        ).yield_per(256):
            yield core._product_from_row(product_row)
        for hardware_row in self.session.scalars(
            select(HardwareModelRow).order_by(HardwareModelRow.id)
        ).yield_per(256):
            yield core._hardware_from_row(hardware_row)
        advisory_query = (
            select(AdvisoryRow).options(selectinload(AdvisoryRow.ranges)).order_by(AdvisoryRow.id)
        )
        # selectinload does not duplicate parent rows, so ``unique`` is not
        # needed; SQLAlchemy forbids combining it with streaming ``yield_per``.
        for advisory_row in self.session.scalars(advisory_query).yield_per(128):
            yield core._advisory_from_row(advisory_row)
        for enrichment_row in self.session.scalars(
            select(EnrichmentRow).order_by(EnrichmentRow.cve_id)
        ).yield_per(256):
            yield core._enrichment_from_row(enrichment_row)
        for eol_row in self.session.scalars(
            select(EoLRecordRow).order_by(EoLRecordRow.id)
        ).yield_per(256):
            yield core._eol_from_row(eol_row)

    def append_export_manifest(self, manifest: object) -> None:
        # Export metadata is represented by the published file/manifest, not a
        # canonical source table.  The API can expose the latest manifest.
        del manifest

    def _save_sync_state(self, source_id: str, **kwargs: Any) -> None:
        core.upsert_source_sync_state(self.session, source_id, **kwargs)

    def _lock_record(self, record: CanonicalRecord) -> None:
        """Serialize one record merge only for the current DB transaction.

        PostgreSQL advisory transaction locks cover first-insert races as well
        as updates.  The streaming repository below commits after each raw
        record, so this lock is never held across network fetches or a whole
        source corpus.  SQLite keeps its normal file locking behavior.
        """

        bind = self.session.get_bind()
        if bind.dialect.name != "postgresql":
            return
        record_type, record_id = _record_identity(record)
        lock_key = f"osak:canonical:{record_type}:{record_id}"
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": lock_key},
        )

    def _lock_raw(self, raw: RawDocument) -> None:
        bind = self.session.get_bind()
        if bind.dialect.name != "postgresql":
            return
        import hashlib

        lock_key = f"osak:raw:{hashlib.sha256(raw.content).hexdigest()}"
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": lock_key},
        )

    def _get_record(self, record: CanonicalRecord) -> CanonicalRecord | None:
        if isinstance(record, Vendor):
            vendor_row = self.session.get(VendorRow, record.id)
            return core._vendor_from_row(vendor_row) if vendor_row else None
        if isinstance(record, Product):
            product_row = self.session.get(ProductRow, record.id)
            return core._product_from_row(product_row) if product_row else None
        if isinstance(record, HardwareModel):
            hardware_row = self.session.get(HardwareModelRow, record.id)
            return core._hardware_from_row(hardware_row) if hardware_row else None
        if isinstance(record, Advisory):
            # Do not call the public id-or-CVE lookup here.  During ingestion
            # two vendor advisories may legitimately share one CVE; a CVE
            # fallback could return the wrong advisory and make Merger reject
            # the identity or overwrite unrelated vendor data.
            statement = (
                select(AdvisoryRow)
                .options(selectinload(AdvisoryRow.ranges))
                .where(AdvisoryRow.id == record.id)
            )
            advisory_row = self.session.scalars(statement).unique().first()
            return core._advisory_from_row(advisory_row) if advisory_row else None
        if isinstance(record, Enrichment):
            enrichment_row = self.session.get(EnrichmentRow, record.cve_id)
            return core._enrichment_from_row(enrichment_row) if enrichment_row else None
        if isinstance(record, EoLRecord):
            eol_row = self.session.get(EoLRecordRow, record.id)
            return core._eol_from_row(eol_row) if eol_row else None
        raise TypeError(type(record).__name__)


SessionFactory = Callable[[], AbstractContextManager[Session]]


class CoreStreamingIngestRepository:
    """Short-transaction adapter for long-running source polls.

    Each raw blob, canonical merge, conflict append and checkpoint update owns
    a separate session scope.  This prevents a slow connector from holding a
    transaction open while it waits on the network, while the canonical merge
    lock still serializes concurrent updates to one record.
    """

    def __init__(self, session_factory: SessionFactory, *, merger: Merger | None = None) -> None:
        self.session_factory = session_factory
        self.merger = merger or Merger()

    def get_checkpoint(self, source_id: str) -> Checkpoint | None:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).get_checkpoint(source_id)

    def commit_checkpoint(self, checkpoint: Checkpoint) -> None:
        with self.session_factory() as session:
            CoreIngestRepository(session, merger=self.merger).commit_checkpoint(checkpoint)

    def put_raw(self, source_id: str, raw: RawDocument) -> RawBlob:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).put_raw(source_id, raw)

    def has_advisory(self, advisory_id: str) -> bool:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).has_advisory(advisory_id)

    def advisory_cve_ids(self, vendors: list[str]) -> set[str]:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).advisory_cve_ids(vendors)

    def merge_record(self, record: CanonicalRecord, context: SourceContext) -> MergeResult:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).merge_record(record, context)

    def append_conflicts(self, conflicts: Iterable[Conflict]) -> None:
        pending = tuple(conflicts)
        if not pending:
            return
        with self.session_factory() as session:
            CoreIngestRepository(session, merger=self.merger).append_conflicts(pending)

    def set_source_status(self, status: SourceStatus) -> None:
        with self.session_factory() as session:
            CoreIngestRepository(session, merger=self.merger).set_source_status(status)

    def get_source_status(self, source_id: str) -> SourceStatus:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).get_source_status(source_id)

    def source_status_at(self, source_id: str, now: datetime) -> SourceStatus:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).source_status_at(
                source_id, now
            )

    def list_source_status(self, now: datetime | None = None) -> list[SourceStatus]:
        with self.session_factory() as session:
            return CoreIngestRepository(session, merger=self.merger).list_source_status(now)

    def iter_records(self) -> Iterator[CanonicalRecord]:
        with self.session_factory() as session:
            yield from CoreIngestRepository(session, merger=self.merger).iter_records()

    def append_export_manifest(self, manifest: object) -> None:
        del manifest


class CoreRawStore:
    """Read/replay adapter for immutable raw rows managed by core."""

    def __init__(self, session: Session, *, source_id: str | None = None) -> None:
        self.session = session
        self.source_id = source_id

    def put(self, source_id: str, raw: RawDocument) -> RawBlob:
        CoreIngestRepository(self.session)._lock_raw(raw)
        row = core.store_raw_document(self.session, raw, source_id=source_id)
        return RawBlob(
            content_hash=row.content_hash,
            source_id=source_id,
            url=row.url,
            fetched_at=_aware(row.fetched_at),
            media_type=row.media_type,
            byte_size=len(row.content),
        )

    def get(self, content_hash: str) -> RawDocument:
        row = self.session.get(RawDocumentRow, content_hash)
        if row is None:
            raise FileNotFoundError(content_hash)
        return RawDocument(
            url=row.url,
            fetched_at=_aware(row.fetched_at),
            content=row.content,
            media_type=row.media_type,
        )

    def iter_hashes(self) -> Iterable[str]:
        statement = select(RawDocumentRow.content_hash).order_by(RawDocumentRow.content_hash)
        yield from self.session.scalars(statement).yield_per(256)


def _status_metadata(status: SourceStatus, *, generation: int) -> dict[str, Any]:
    return {
        "generation": generation,
        "enabled": status.enabled,
        "allowed": status.allowed,
        "policy_state": status.state if status.state in {"disabled", "unapproved"} else None,
        "detail": status.detail,
        "schedule_seconds": status.schedule_seconds,
        "stale_after_seconds": status.stale_after_seconds,
        "next_due_at": status.next_due_at.isoformat() if status.next_due_at else None,
        "consecutive_failures": status.consecutive_failures,
        "license_name": status.license_name,
        "license_url": status.license_url,
        "attribution": status.attribution,
        "redistribution": status.redistribution,
        "kind": status.kind,
        "vendor_scope": list(status.vendor_scope),
        "operator_excluded": status.operator_excluded,
    }


def _record_identity(record: CanonicalRecord) -> tuple[str, str]:
    if isinstance(record, Vendor):
        return "vendor", record.id
    if isinstance(record, Product):
        return "product", record.id
    if isinstance(record, HardwareModel):
        return "hardware_model", record.id
    if isinstance(record, Advisory):
        return "advisory", record.id
    if isinstance(record, Enrichment):
        return "enrichment", record.cve_id
    if isinstance(record, EoLRecord):
        return "eol", record.id
    raise TypeError(type(record).__name__)


def _cursor_text(cursor: datetime | str | None) -> str | None:
    return cursor.isoformat() if isinstance(cursor, datetime) else cursor


def _cursor_value(cursor: str) -> datetime | str:
    try:
        parsed = datetime.fromisoformat(cursor)
    except ValueError:
        return cursor
    return _aware(parsed)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
