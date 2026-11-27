#!/usr/bin/env python3
"""Import an authentic CVE List V5 daily archive as one locked source job.

Raw and canonical writes commit in bounded per-document transactions through
the streaming repository. The source checkpoint is deliberately ignored until
the full archive poll completes; a failure therefore leaves the old cursor in
place, while retrying is safe because writes are content-addressed/upserted.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from osak.connectors.base import RawDocument
from osak.connectors.cvelistv5 import CveListV5Connector
from osak.core.db import session_scope
from osak.ingest.core_adapter import CoreStreamingIngestRepository
from osak.ingest.policy import PublicationPolicy
from osak.ingest.worker import IngestWorker


class _ProgressConnector:
    def __init__(self, connector: CveListV5Connector) -> None:
        self.connector = connector
        self.seen = 0

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self.connector, name)

    def fetch(self, since):  # type: ignore[no-untyped-def]
        for raw in self.connector.fetch(since):
            self.seen += 1
            if self.seen == 1 or self.seen % 1000 == 0:
                print(f"cvelistv5_documents_seen={self.seen}", flush=True)
            yield raw

    def normalize(self, raw: RawDocument) -> Iterable[object]:
        return self.connector.normalize(raw)


class _BaselineRepository(CoreStreamingIngestRepository):
    """Force a full archive fetch without deleting the persisted cursor."""

    def get_checkpoint(self, source_id: str):  # type: ignore[no-untyped-def]
        if source_id == "cvelistv5":
            return None
        return super().get_checkpoint(source_id)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--archive-path",
        type=Path,
        default=Path("/var/lib/osak/data/baselines/cvelistv5-latest.zip"),
    )
    args = parser.parse_args()
    connector = _ProgressConnector(
        CveListV5Connector(bootstrap_path=args.archive_path)
    )
    policy = PublicationPolicy.from_env()
    repository = _BaselineRepository(session_scope)
    result = IngestWorker({"cvelistv5": connector}, repository, policy=policy).poll("cvelistv5")
    print(
        {
            "source_id": result.source_id,
            "success": result.success,
            "documents_seen": result.documents_seen,
            "records_seen": result.records_seen,
            "cursor": result.checkpoint.cursor.isoformat() if result.checkpoint else None,
            "archive_path": str(args.archive_path),
            "error": result.error,
        },
        flush=True,
    )
    if not result.success:
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
