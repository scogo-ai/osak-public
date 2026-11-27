"""Scheduled, retry-safe connector polling."""

from __future__ import annotations

import os
import random
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Any

import httpx
from pydantic import TypeAdapter
from sqlalchemy.exc import StatementError

from osak.connectors.base import Connector, RawDocument
from osak.core.models import Enrichment
from osak.ingest.merge import SourceContext
from osak.ingest.normalize import normalize_document
from osak.ingest.persistence import IngestRepository
from osak.ingest.policy import PublicationPolicy
from osak.ingest.types import Checkpoint, SourceStatus

_RAW_ADAPTER = TypeAdapter(RawDocument)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_delay: float = 1.0
    multiplier: float = 2.0
    max_delay: float = 60.0
    jitter: float = 0.1

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        if self.initial_delay < 0 or self.multiplier < 1 or self.max_delay < 0 or self.jitter < 0:
            raise ValueError("retry delays and jitter must be non-negative; multiplier must be >= 1")

    def delay(self, failed_attempt: int, random_value: Callable[[], float] = random.random) -> float:
        base = min(self.max_delay, self.initial_delay * self.multiplier ** max(failed_attempt - 1, 0))
        return base + base * self.jitter * random_value()


@dataclass(frozen=True, slots=True)
class PollResult:
    source_id: str
    success: bool
    blocked: bool = False
    attempts: int = 0
    documents_seen: int = 0
    records_seen: int = 0
    checkpoint: Checkpoint | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class _AttemptResult:
    documents_seen: int
    records_seen: int
    latest_document_at: datetime | None


class IngestWorker:
    """Poll connectors and commit only fully successful checkpoints."""

    def __init__(
        self,
        connectors: Mapping[str, Connector],
        repository: IngestRepository,
        *,
        raw_store: Any | None = None,
        policy: PublicationPolicy | None = None,
        retry: RetryPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        stale_factor: int = 3,
        source_roles: Mapping[str, str] | None = None,
    ) -> None:
        self.connectors = dict(connectors)
        self.repository = repository
        self.raw_store = raw_store
        self.policy = policy or PublicationPolicy.from_env()
        self.retry = retry or RetryPolicy()
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sleeper = sleeper or time.sleep
        self.stale_factor = stale_factor
        self.source_roles = dict(source_roles or {})
        if stale_factor < 1:
            raise ValueError("stale_factor must be at least one")

    def poll(self, source_id: str, *, force: bool = False) -> PollResult:
        del force  # A direct poll is always explicit; scheduling decides due-ness.
        try:
            connector = self.connectors[source_id]
        except KeyError as exc:
            raise KeyError(f"unknown connector {source_id!r}") from exc
        now = self.clock()
        schedule = _schedule_seconds(connector)
        stale_after = schedule * self.stale_factor
        decision = self.policy.evaluate(connector)
        if not decision.allowed:
            status = self._status(
                connector,
                now=now,
                state=decision.state,
                allowed=False,
                enabled=False,
                detail=decision.reason,
                schedule=schedule,
                stale_after=stale_after,
            )
            self.repository.set_source_status(status)
            return PollResult(source_id, success=False, blocked=True, error=decision.reason)

        previous = self.repository.get_checkpoint(source_id)
        if previous is None:
            self.repository.set_source_status(self._status(
                connector, now=now, state="running", allowed=True, enabled=True,
                detail="Initial source synchronization in progress",
                schedule=schedule, stale_after=stale_after,
            ))
        since = _fetch_cursor(previous.cursor) if previous and previous.cursor is not None else (
            previous.last_success_at if previous else None
        )
        last_error: Exception | None = None
        documents_seen = records_seen = 0
        latest_document_at: datetime | None = None
        attempts_used = 0
        for attempt in range(1, self.retry.max_attempts + 1):
            attempts_used = attempt
            try:
                result = self._attempt(connector, since)
                documents_seen = result.documents_seen
                records_seen = result.records_seen
                latest_document_at = result.latest_document_at
                checkpoint = Checkpoint(
                    source_id=source_id,
                    cursor=latest_document_at or (previous.cursor if previous else None) or now,
                    last_success_at=self.clock(),
                    generation=(previous.generation + 1 if previous else 1),
                )
                status = self._status(
                    connector,
                    now=now,
                    state="healthy",
                    allowed=True,
                    enabled=True,
                    detail="poll succeeded",
                    schedule=schedule,
                    stale_after=stale_after,
                    previous=previous,
                    checkpoint=checkpoint,
                    documents_seen=documents_seen,
                    records_seen=records_seen,
                )
                self._commit_poll(checkpoint, status)
                return PollResult(
                    source_id,
                    success=True,
                    attempts=attempt,
                    documents_seen=documents_seen,
                    records_seen=records_seen,
                    checkpoint=checkpoint,
                )
            except Exception as exc:  # noqa: BLE001 - connector failures become retry/status data
                if not is_retryable(exc):
                    last_error = exc
                    break
                last_error = exc
                if attempt < self.retry.max_attempts:
                    self.sleeper(self.retry.delay(attempt))

        error = _error_text(last_error)
        status = self._status(
            connector,
            now=now,
            state="unavailable",
            allowed=True,
            enabled=True,
            detail=f"poll failed after {attempts_used} attempts: {error}",
            schedule=schedule,
            stale_after=stale_after,
            previous=previous,
            documents_seen=documents_seen,
            records_seen=records_seen,
        )
        self.repository.set_source_status(status)
        return PollResult(
            source_id,
            success=False,
            attempts=attempts_used,
            documents_seen=documents_seen,
            records_seen=records_seen,
            error=error,
        )

    def poll_due(self, *, now: datetime | None = None) -> list[PollResult]:
        current = now or self.clock()
        results: list[PollResult] = []
        for source_id, connector in sorted(self.connectors.items()):
            decision = self.policy.evaluate(connector)
            if not decision.allowed:
                # Persist policy status even when a scheduled run has no due
                # work, so the API can distinguish excluded from stale.
                if _status_missing(self.repository, source_id):
                    self.poll(source_id)
                continue
            if _is_due(self.repository, source_id, current):
                results.append(self.poll(source_id))
        return results

    def run_once(self, *, now: datetime | None = None) -> list[PollResult]:
        result = self.poll_due(now=now)
        write_heartbeat()
        return result

    def run_forever(self, stop: Event | None = None, *, max_sleep: float = 60.0) -> None:
        """Run scheduled polls until ``stop`` is set.

        The loop uses the shortest connector schedule as its wake-up bound;
        source-specific ``next_due_at`` values remain the authority for work.
        """

        stop_event = stop or Event()
        schedules = [_schedule_seconds(connector) for connector in self.connectors.values()]
        interval = min(schedules, default=60)
        while not stop_event.is_set():
            self.run_once()
            stop_event.wait(timeout=min(max_sleep, max(0.1, interval)))

    def _attempt(self, connector: Connector, since: datetime | None) -> _AttemptResult:
        documents_seen = records_seen = 0
        latest: datetime | None = None
        accepts_document = getattr(connector, "accepts_document", None)
        has_advisory = self.repository.has_advisory if accepts_document and since else None
        epss_targets = (
            self.repository.advisory_cve_ids(connector.vendor_scope)
            if connector.id == "first_epss" and "*" not in connector.vendor_scope
            else None
        )
        # Do not convert this iterable to a list: cvelistV5 can contain a very
        # large corpus.  One raw document and one normalized record are held at
        # a time, with content-addressed storage making retries idempotent.
        for candidate in connector.fetch(since):
            raw = _RAW_ADAPTER.validate_python(candidate)
            documents_seen += 1
            latest = raw.fetched_at if latest is None else max(latest, raw.fetched_at)
            if accepts_document is not None and not accepts_document(raw, has_advisory=has_advisory):
                continue
            if self.raw_store is not None:
                self.raw_store.put(connector.id, raw)
            else:
                self.repository.put_raw(connector.id, raw)
            context = SourceContext(
                source=connector.id,
                fetched_at=raw.fetched_at,
                url=raw.url,
                license=connector.license.name,
                role=self.source_roles.get(connector.id),
            )
            for record in normalize_document(connector, raw, context=context):
                if (
                    epss_targets is not None
                    and isinstance(record, Enrichment)
                    and record.cve_id not in epss_targets
                ):
                    continue
                result = self.repository.merge_record(record, context)
                if result.conflicts:
                    self.repository.append_conflicts(result.conflicts)
                records_seen += 1
        return _AttemptResult(documents_seen, records_seen, latest)

    def _commit_poll(self, checkpoint: Checkpoint, status: SourceStatus) -> None:
        commit = getattr(self.repository, "commit_poll", None)
        if commit is not None:
            commit(checkpoint, status)
            return
        # Implementations without a combined transaction still receive the
        # checkpoint only after all raw and normalized writes completed.
        self.repository.commit_checkpoint(checkpoint)
        self.repository.set_source_status(status)

    def _status(
        self,
        connector: Connector,
        *,
        now: datetime,
        state: str,
        allowed: bool,
        enabled: bool,
        detail: str,
        schedule: int,
        stale_after: int,
        previous: Checkpoint | None = None,
        checkpoint: Checkpoint | None = None,
        documents_seen: int = 0,
        records_seen: int = 0,
    ) -> SourceStatus:
        old = None
        try:
            old = self.repository.get_source_status(connector.id)
        except KeyError:
            pass
        previous_failures = old.consecutive_failures if old is not None else 0
        if state == "healthy":
            failures = 0
        elif state == "unavailable":
            failures = previous_failures + 1
        else:
            failures = previous_failures
        last_success = checkpoint.last_success_at if checkpoint else (
            previous.last_success_at if previous else (old.last_success_at if old else None)
        )
        finished_at = checkpoint.last_success_at if checkpoint else now
        next_due = finished_at + timedelta(seconds=schedule) if state == "healthy" else None
        license_info = connector.license
        return SourceStatus(
            source_id=connector.id,
            enabled=enabled,
            allowed=allowed,
            state=state,  # type: ignore[arg-type]
            detail=detail,
            schedule_seconds=schedule,
            stale_after_seconds=stale_after,
            last_attempt_at=now,
            last_success_at=last_success,
            next_due_at=next_due,
            updated_at=finished_at,
            consecutive_failures=failures,
            documents_seen=documents_seen,
            records_seen=records_seen,
            license_name=license_info.name,
            license_url=license_info.url,
            attribution=license_info.attribution,
            redistribution=license_info.redistribution,
            kind=connector.kind,
            vendor_scope=list(connector.vendor_scope),
            operator_excluded=state in {"disabled", "unapproved"} or not allowed or not enabled,
        )


def is_retryable(exc: BaseException) -> bool:
    """Classify transport/rate-limit failures without retrying bad data."""

    if isinstance(exc, (TimeoutError, ConnectionError, OSError, RetryableError, httpx.RequestError)):
        return True
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return status in {408, 425, 429} or (isinstance(status, int) and status >= 500)


class RetryableError(RuntimeError):
    """Connector exception for explicitly transient failures."""


def _schedule_seconds(connector: Connector) -> int:
    try:
        schedule = int(connector.schedule)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"connector {connector.id!r} has an invalid schedule") from exc
    if schedule <= 0:
        raise ValueError(f"connector {connector.id!r} schedule must be positive")
    return schedule


def _status_missing(repository: IngestRepository, source_id: str) -> bool:
    try:
        repository.get_source_status(source_id)
    except KeyError:
        return True
    return False


def _is_due(repository: IngestRepository, source_id: str, now: datetime) -> bool:
    try:
        status = repository.source_status_at(source_id, now)
    except KeyError:
        return True
    # The caller has already applied current policy. An old exclusion must
    # not prevent the first poll after the source is approved.
    return (
        status.state in {"disabled", "unapproved"}
        or status.next_due_at is None
        or now >= status.next_due_at
    )


def _error_text(exc: BaseException | None) -> str:
    if exc is None:
        return "unknown error"
    if isinstance(exc, StatementError):
        # A driver exception can include the entire statement and bound data.
        return f"Database write failed ({type(exc.orig).__name__})"
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _fetch_cursor(cursor: datetime | str) -> datetime | None:
    if isinstance(cursor, datetime):
        return cursor
    try:
        value = datetime.fromisoformat(cursor)
    except ValueError:
        # The current Connector protocol accepts datetime cursors.  Opaque
        # provider tokens are retained for persistence but cannot safely be
        # passed to a connector that has not opted into them yet.
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def write_heartbeat(
    path: str | os.PathLike[str] | None = None,
    *,
    now: datetime | None = None,
) -> None:
    """Atomically write a timestamp-only scheduler heartbeat when configured."""

    configured = path or os.getenv("OSAK_WORKER_HEARTBEAT_FILE")
    if not configured:
        return
    destination = Path(configured)
    destination.parent.mkdir(parents=True, exist_ok=True)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    timestamp = current.astimezone(UTC).isoformat().encode("ascii") + b"\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(timestamp)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

