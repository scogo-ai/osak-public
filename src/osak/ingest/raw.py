"""Immutable content-addressed storage for connector raw documents."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from osak.connectors.base import RawDocument
from osak.ingest.types import RawBlob


class RawStoreError(RuntimeError):
    """Raised when an immutable raw document cannot be safely stored."""


class FileRawStore:
    """Store raw bytes below ``root`` using SHA-256 content addressing.

    Existing content is never overwritten.  The first writer atomically
    installs both the bytes and metadata; later writes of the same hash are
    accepted only if the bytes still match, which detects accidental tampering
    rather than silently repairing it.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def content_path(self, content_hash: str) -> Path:
        _validate_hash(content_hash)
        return self.root / content_hash[:2] / f"{content_hash}.bin"

    def metadata_path(self, content_hash: str) -> Path:
        _validate_hash(content_hash)
        return self.root / content_hash[:2] / f"{content_hash}.json"

    def put(self, source_id: str, raw: RawDocument) -> RawBlob:
        content_hash = hashlib.sha256(raw.content).hexdigest()
        destination = self.content_path(content_hash)
        metadata = self.metadata_path(content_hash)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            if destination.read_bytes() != raw.content:
                raise ValueError(f"raw document {content_hash} is immutable and was modified")
        else:
            _atomic_write(destination, raw.content)

        blob = RawBlob(
            content_hash=content_hash,
            source_id=source_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            media_type=raw.media_type,
            byte_size=len(raw.content),
        )
        if metadata.exists():
            try:
                old = json.loads(metadata.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RawStoreError(f"invalid metadata for immutable raw document {content_hash}") from exc
            if old.get("content_hash") != content_hash:
                raise RawStoreError(f"metadata hash mismatch for immutable raw document {content_hash}")
        else:
            _atomic_write(metadata, json.dumps(blob.model_dump(mode="json"), sort_keys=True).encode())
        return blob

    def get(self, content_hash: str) -> RawDocument:
        destination = self.content_path(content_hash)
        metadata = self.metadata_path(content_hash)
        if not destination.exists() or not metadata.exists():
            raise FileNotFoundError(content_hash)
        details = json.loads(metadata.read_text(encoding="utf-8"))
        content = destination.read_bytes()
        if hashlib.sha256(content).hexdigest() != content_hash:
            raise RawStoreError(f"raw document {content_hash} failed integrity check")
        return RawDocument(
            url=details["url"],
            fetched_at=details["fetched_at"],
            content=content,
            media_type=details.get("media_type", "application/json"),
        )

    def iter_hashes(self) -> Iterable[str]:
        for path in sorted(self.root.glob("??/*.bin")):
            name = path.stem
            if len(name) == 64:
                yield name


class InMemoryRawStore:
    """Small test/dev raw store with the same immutability semantics."""

    def __init__(self) -> None:
        self._documents: dict[str, tuple[RawBlob, RawDocument]] = {}

    def put(self, source_id: str, raw: RawDocument) -> RawBlob:
        content_hash = hashlib.sha256(raw.content).hexdigest()
        blob = RawBlob(
            content_hash=content_hash,
            source_id=source_id,
            url=raw.url,
            fetched_at=raw.fetched_at,
            media_type=raw.media_type,
            byte_size=len(raw.content),
        )
        existing = self._documents.get(content_hash)
        if existing is not None and existing[1].content != raw.content:
            raise ValueError(f"raw document {content_hash} is immutable and was modified")
        if existing is None:
            self._documents[content_hash] = (blob, raw)
        return blob

    def get(self, content_hash: str) -> RawDocument:
        try:
            return self._documents[content_hash][1]
        except KeyError as exc:
            raise FileNotFoundError(content_hash) from exc

    def iter_hashes(self) -> Iterable[str]:
        yield from sorted(self._documents)


def _validate_hash(content_hash: str) -> None:
    if len(content_hash) != 64 or any(char not in "0123456789abcdef" for char in content_hash):
        raise ValueError("content hash must be a lowercase SHA-256 hex digest")


def _atomic_write(path: Path, content: bytes) -> None:
    """Write ``content`` and atomically publish it at ``path``."""

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

