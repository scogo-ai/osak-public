"""Run the OSAK ingestion worker with ``python -m osak.ingest``."""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any, cast

from osak.connectors.base import discover
from osak.ingest.core_adapter import CoreIngestRepository
from osak.ingest.export import DatasetExporter, NightlyExportScheduler, NightlyMaintenance
from osak.ingest.persistence import InMemoryRepository
from osak.ingest.policy import PublicationPolicy
from osak.ingest.raw import FileRawStore
from osak.ingest.scheduler import DatabaseSourceScheduler
from osak.ingest.worker import IngestWorker, PollResult, write_heartbeat


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Poll OSAK advisory connectors")
    parser.add_argument("--once", action="store_true", help="poll due connectors once and exit")
    parser.add_argument("--export", action="store_true", help="publish a checksummed JSONL snapshot after polling")
    parser.add_argument("--data-dir", type=Path, default=Path(os.getenv("OSAK_DATA_DIR", "data")))
    parser.add_argument("--source", action="append", dest="sources", help="limit polling to this connector id")
    parser.add_argument("--public", action="store_true", help="apply public-instance publication policy")
    parser.add_argument(
        "--memory",
        action="store_true",
        help="use an ephemeral in-memory repository (tests/dev only; Postgres is the default)",
    )
    parser.add_argument("--interval", type=float, default=60.0, help="daemon wake-up interval in seconds")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=int(os.getenv("OSAK_INGEST_MAX_WORKERS", "4")),
        help="maximum concurrent source polls in daemon/one-shot mode",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    connectors = discover()
    if os.getenv("INGEST_ENABLED", "true").strip().lower() in {"0", "false", "no", "off"}:
        connectors = {}
    if args.max_workers < 1:
        raise SystemExit("--max-workers must be positive")
    if args.sources:
        wanted = set(args.sources)
        missing = sorted(wanted - set(connectors))
        if missing:
            print(f"unknown connector source(s): {', '.join(missing)}", file=sys.stderr)
            return 2
        connectors = {source_id: connector for source_id, connector in connectors.items() if source_id in wanted}
    policy = PublicationPolicy.from_env()
    if args.public:
        policy = PublicationPolicy(
            public=True,
            reviewed_source_ids=policy.reviewed_source_ids,
            disabled_source_ids=policy.disabled_source_ids,
            enabled_source_ids=policy.enabled_source_ids,
            allow_paid_private=False,
        )
    if args.interval <= 0:
        raise SystemExit("--interval must be positive")

    if args.memory:
        return _run_memory(args, connectors, policy)

    if args.once:
        results = _run_database_cycle(connectors, policy, max_workers=args.max_workers)
        if args.export:
            _run_database_export(args.data_dir / "exports")
        return 0 if all(result.success for result in results) else 1

    stop = Event()
    scheduler = DatabaseSourceScheduler(connectors, policy, max_workers=args.max_workers)
    nightly = NightlyMaintenance(
        NightlyExportScheduler(_DatabaseExporterFactory(args.data_dir / "exports"), hour_utc=2),
        rollup=_run_accounts_rollup,
    )
    maintenance_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="osak-maintenance")
    maintenance_future: Future[object] | None = None
    try:
        while not stop.is_set():
            scheduler.tick()
            write_heartbeat()
            if maintenance_future is not None and maintenance_future.done():
                _log_maintenance_result(maintenance_future)
                maintenance_future = None
            if maintenance_future is None:
                maintenance_future = maintenance_executor.submit(nightly.run_once)
            stop.wait(timeout=args.interval)
    finally:
        scheduler.close(wait_for_tasks=True)
        if maintenance_future is not None:
            maintenance_future.cancel()
        maintenance_executor.shutdown(wait=False, cancel_futures=True)
    return 0


def _run_memory(args: argparse.Namespace, connectors: dict[str, Any], policy: PublicationPolicy) -> int:
    repository = InMemoryRepository()
    raw_store = FileRawStore(args.data_dir / "raw")
    worker = IngestWorker(connectors, repository, raw_store=raw_store, policy=policy)
    if args.once:
        results = worker.run_once()
        if args.export:
            DatasetExporter(repository, args.data_dir / "exports").export()
        return 0 if all(result.success for result in results) else 1
    else:
        worker.run_forever()
    if args.export:
        DatasetExporter(repository, args.data_dir / "exports").export()
    return 0


def _run_database_cycle(
    connectors: dict[str, Any],
    policy: PublicationPolicy,
    *,
    max_workers: int = 4,
) -> list[PollResult]:
    """Run a one-shot bounded poll and wait for all selected sources."""

    scheduler = DatabaseSourceScheduler(connectors, policy, max_workers=max_workers)
    try:
        results = scheduler.run_once()
        write_heartbeat()
        return results
    finally:
        scheduler.close(wait_for_tasks=True)


def _run_database_export(output_dir: Path) -> None:
    from osak.core.db import session_scope

    with session_scope(isolation_level="REPEATABLE READ") as session:
        repository = CoreIngestRepository(session)
        DatasetExporter(repository, output_dir).export()


class _DatabaseExporterFactory:
    """Lazy exporter used by the long-running daemon's nightly scheduler."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def export(self, *, generated_at=None):  # type: ignore[no-untyped-def]
        from osak.core.db import session_scope

        with session_scope(isolation_level="REPEATABLE READ") as session:
            exporter = DatasetExporter(CoreIngestRepository(session), self.output_dir)
            return exporter.export(generated_at=generated_at)


def _run_accounts_rollup(now: Any) -> object | None:
    """Run the accounts-owned 90-day metadata rollup in its own transaction."""

    from osak.accounts.service import roll_up_usage
    from osak.core.db import session_scope

    with session_scope() as session:
        return cast(object, roll_up_usage(session, now=now))


def _log_maintenance_result(future: Future[object]) -> None:
    try:
        future.result()
    except Exception as exc:  # noqa: BLE001 - daemon keeps polling after maintenance failure
        print(f"nightly maintenance failed: {type(exc).__name__}: {exc}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

