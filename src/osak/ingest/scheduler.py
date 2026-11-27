"""Bounded per-source scheduling for the persistent worker process."""

from __future__ import annotations

import os
from collections import deque
from collections.abc import Callable, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass

from osak.connectors.base import Connector
from osak.ingest.core_adapter import CoreStreamingIngestRepository
from osak.ingest.policy import PublicationPolicy
from osak.ingest.worker import IngestWorker, PollResult

Poller = Callable[[str, Connector, PublicationPolicy], list[PollResult]]


def poll_source_in_database(
    source_id: str,
    connector: Connector,
    policy: PublicationPolicy,
) -> list[PollResult]:
    """Poll one source with a session owned exclusively by that task."""

    from osak.core.db import session_scope

    repository = CoreStreamingIngestRepository(session_scope)
    worker = IngestWorker({source_id: connector}, repository, policy=policy)
    return worker.run_once()


@dataclass(frozen=True, slots=True)
class SchedulerError:
    source_id: str
    error: str


class DatabaseSourceScheduler:
    """Bound source polling without allowing one source to block all others.

    At most ``max_workers`` source sessions are active.  A source is removed
    from the active set only after its future completes, so the same source can
    never be polled concurrently.  Daemon ``tick`` calls do not wait for slow
    sources; one-shot ``run_once`` deliberately waits for its selected set.
    """

    def __init__(
        self,
        connectors: Mapping[str, Connector],
        policy: PublicationPolicy,
        *,
        max_workers: int | None = None,
        poller: Poller = poll_source_in_database,
    ) -> None:
        self.connectors = dict(connectors)
        configured = max_workers
        if configured is None:
            configured = _configured_workers()
        if configured < 1:
            raise ValueError("max_workers must be positive")
        self.max_workers = min(configured, max(1, len(self.connectors)))
        self.policy = policy
        self.poller = poller
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="osak-ingest")
        self._pending = deque(sorted(self.connectors))
        self._active: dict[str, Future[list[PollResult]]] = {}
        self._closed = False

    @property
    def active_source_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._active))

    def tick(self) -> list[PollResult]:
        """Collect completed work and start due checks without waiting."""

        if self._closed:
            return []
        results = self._collect_done(requeue=True)
        self._fill_slots()
        return results

    def run_once(self) -> list[PollResult]:
        """Poll every selected source once, with bounded parallelism."""

        if self._closed:
            raise RuntimeError("scheduler is closed")
        pending = deque(sorted(self.connectors))
        active: dict[str, Future[list[PollResult]]] = {}
        results: list[PollResult] = []
        while pending or active:
            while pending and len(active) < self.max_workers:
                source_id = pending.popleft()
                active[source_id] = self._submit(source_id)
            if not active:
                continue
            done, _ = wait(tuple(active.values()), return_when=FIRST_COMPLETED)
            for future in done:
                source_id = next(item for item, candidate in active.items() if candidate is future)
                del active[source_id]
                results.extend(_future_results(source_id, future))
        return results

    def close(self, *, wait_for_tasks: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        self._executor.shutdown(wait=wait_for_tasks, cancel_futures=not wait_for_tasks)

    def _fill_slots(self) -> None:
        while self._pending and len(self._active) < self.max_workers:
            source_id = self._pending.popleft()
            if source_id not in self._active:
                self._active[source_id] = self._submit(source_id)

    def _submit(self, source_id: str) -> Future[list[PollResult]]:
        return self._executor.submit(
            self.poller,
            source_id,
            self.connectors[source_id],
            self.policy,
        )

    def _collect_done(self, *, requeue: bool) -> list[PollResult]:
        done = [future for future in self._active.values() if future.done()]
        results: list[PollResult] = []
        for future in done:
            source_id = next(item for item, candidate in self._active.items() if candidate is future)
            del self._active[source_id]
            results.extend(_future_results(source_id, future))
            if requeue and not self._closed:
                self._pending.append(source_id)
        return results


def _future_results(source_id: str, future: Future[list[PollResult]]) -> list[PollResult]:
    try:
        return future.result()
    except Exception as exc:  # noqa: BLE001 - scheduler records task failure as source status
        return [PollResult(source_id=source_id, success=False, error=f"{type(exc).__name__}: {exc}")]


def _configured_workers() -> int:
    value = os.getenv("OSAK_INGEST_MAX_WORKERS", "4")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("OSAK_INGEST_MAX_WORKERS must be an integer") from exc
    if parsed < 1:
        raise ValueError("OSAK_INGEST_MAX_WORKERS must be positive")
    return parsed

