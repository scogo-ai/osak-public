"""Small, persistence-neutral types used by the ingestion worker.

The worker deliberately keeps these types independent from SQLAlchemy.  The
core package can provide a database-backed implementation of the repository
protocol without making connectors or the offline dataset exporter depend on a
database driver.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class IngestModel(BaseModel):
    """Base model for worker metadata.

    Worker metadata is persisted and later exposed through API status routes,
    so silently accepting misspelled fields would make operations misleading.
    """

    model_config = ConfigDict(extra="forbid")


SourceState = Literal[
    "healthy",
    "stale",
    "unavailable",
    "never_synced",
    "running",
    "disabled",
    "unapproved",
]


class Checkpoint(IngestModel):
    """The last fully successful cursor for one connector.

    ``cursor`` is passed back to ``Connector.fetch``.  It is only advanced
    after every document in a poll has been stored and normalized.  A failed
    attempt therefore keeps the previous cursor and is safe to retry.
    """

    source_id: str = Field(min_length=1)
    # Connectors currently accept datetime cursors.  The core sync table keeps
    # this as text as well so a connector may later use an opaque provider
    # token without changing the persistence boundary.
    cursor: AwareDatetime | str | None = None
    last_success_at: AwareDatetime
    generation: int = Field(default=0, ge=0)


class RawBlob(IngestModel):
    """Metadata for an immutable content-addressed raw document."""

    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_id: str = Field(min_length=1)
    url: str
    fetched_at: AwareDatetime
    media_type: str = "application/json"
    byte_size: int = Field(ge=0)


class Conflict(IngestModel):
    """A field disagreement retained for operator review.

    Values are JSON-compatible snapshots.  Raw source documents are never
    embedded here; conflict logging is limited to normalized structured facts.
    """

    record_type: str
    record_id: str
    field: str
    kept_value: object
    incoming_value: object
    kept_source: str
    incoming_source: str
    kept_precedence: int
    incoming_precedence: int
    detected_at: AwareDatetime
    losing_source: str = ""
    losing_value: object = None

    @property
    def winner_source(self) -> str:
        """Core repository naming for the selected source."""

        return self.kept_source

    @property
    def loser_source(self) -> str:
        """Core repository naming for the rejected source."""

        return self.losing_source or self.incoming_source

    @property
    def winning_value(self) -> object:
        return self.kept_value


class SourceStatus(IngestModel):
    """Operational status of a connector, including policy decisions."""

    source_id: str = Field(min_length=1)
    enabled: bool
    allowed: bool
    state: SourceState
    detail: str = ""
    schedule_seconds: int = Field(gt=0)
    stale_after_seconds: int = Field(gt=0)
    last_attempt_at: AwareDatetime | None = None
    last_success_at: AwareDatetime | None = None
    next_due_at: AwareDatetime | None = None
    updated_at: AwareDatetime
    consecutive_failures: int = Field(default=0, ge=0)
    documents_seen: int = Field(default=0, ge=0)
    records_seen: int = Field(default=0, ge=0)
    license_name: str = ""
    license_url: str = ""
    attribution: str = ""
    redistribution: str = "review"
    kind: Literal["advisory", "enrichment", "eol"] | None = None
    vendor_scope: list[str] = []
    operator_excluded: bool = False

    def at(self, now: datetime) -> SourceStatus:
        """Return a copy with staleness recalculated for ``now``.

        A source blocked by publication policy remains blocked even if time has
        passed.  This keeps ``/sources`` honest instead of reporting a blocked
        source as merely stale.
        """

        if self.state in {"disabled", "unapproved"} or not self.allowed:
            return self
        if self.last_success_at is None:
            state: SourceState = "never_synced"
        elif (now - self.last_success_at).total_seconds() > self.stale_after_seconds:
            state = "stale"
        elif self.consecutive_failures:
            state = "unavailable"
        else:
            state = "healthy"
        next_due = self.last_success_at
        if next_due is not None:
            from datetime import timedelta

            next_due = next_due + timedelta(seconds=self.schedule_seconds)
        return self.model_copy(update={"state": state, "next_due_at": next_due, "updated_at": now})


class ExportManifest(IngestModel):
    """Checksummed publication metadata for one offline dataset snapshot."""

    schema_version: str = "1"
    generated_at: AwareDatetime
    # These are relative object names, never host filesystem paths.  API code
    # should expose ``download_url`` only after authentication.
    dataset_path: str
    manifest_path: str
    download_url: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_count: int = Field(ge=0)
    record_count: int = Field(ge=0)
    record_types: dict[str, int] = {}
    source_ids: list[str] = []
    license_notices: list[dict[str, str]] = []
    source_statuses: list[dict[str, object]] = []
    unavailable_sources: list[str] = []


class Rollup(IngestModel):
    """Daily aggregate of request metadata older than the retention window."""

    day: date
    user_id: str
    key_id: str | None = None
    route: str
    request_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    total_latency_ms: int = Field(ge=0)
    total_response_size: int = Field(ge=0)


def utc_now() -> datetime:
    """Return an aware UTC timestamp suitable for persisted worker metadata."""

    return datetime.now(UTC)

