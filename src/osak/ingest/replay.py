"""Replay immutable raw documents through current normalization code."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from osak.connectors.base import Connector
from osak.ingest.merge import SourceContext
from osak.ingest.normalize import normalize_document
from osak.ingest.persistence import IngestRepository


@dataclass(frozen=True, slots=True)
class ReplayResult:
    source_id: str
    documents_seen: int
    records_seen: int


class RawReplayer:
    """Re-normalize stored source material without advancing poll cursors."""

    def __init__(self, raw_store: Any, repository: IngestRepository) -> None:
        self.raw_store = raw_store
        self.repository = repository

    def replay(
        self,
        connector: Connector,
        *,
        content_hashes: Iterable[str] | None = None,
    ) -> ReplayResult:
        hashes = content_hashes if content_hashes is not None else self.raw_store.iter_hashes()
        documents = records = 0
        for content_hash in hashes:
            raw = self.raw_store.get(content_hash)
            documents += 1
            context = SourceContext(
                source=connector.id,
                fetched_at=raw.fetched_at,
                url=raw.url,
                license=connector.license.name,
            )
            for record in normalize_document(connector, raw, context=context):
                result = self.repository.merge_record(record, context)
                if result.conflicts:
                    self.repository.append_conflicts(result.conflicts)
                records += 1
        return ReplayResult(connector.id, documents, records)

