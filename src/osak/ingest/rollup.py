"""Privacy-preserving usage metadata retention and daily rollups."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import date, datetime, timedelta
from typing import Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from osak.ingest.types import Rollup


class UsageMetadata(BaseModel):
    """Allow-listed request metadata; request bodies have no representable field."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    user_id: str
    key_id: str | None = None
    timestamp: AwareDatetime
    method: str
    route: str
    status: int = Field(ge=100, le=599)
    latency_ms: int = Field(ge=0)
    response_size: int = Field(ge=0)
    asset_count: int | None = Field(default=None, ge=0)
    mcp_tool: str | None = None
    user_agent: str | None = None
    ip_hash: str | None = None


class UsageMetadataStore(Protocol):
    """Adapter surface implemented by the accounts persistence layer."""

    def iter_usage_before(self, cutoff: datetime) -> Iterable[UsageMetadata]: ...

    def upsert_daily_rollups(self, rollups: Iterable[Rollup]) -> None: ...

    def delete_usage_before(self, cutoff: datetime) -> None: ...


def roll_up_metadata(
    records: Iterable[UsageMetadata],
    *,
    now: datetime,
    retention_days: int = 90,
) -> tuple[list[Rollup], list[UsageMetadata]]:
    """Aggregate metadata older than the retention window and retain recent rows.

    The function consumes an iterable and returns only the recent rows, never
    retaining request bodies because :class:`UsageMetadata` rejects unknown
    fields.  A database adapter can write each returned rollup and delete the
    old rows in one transaction.
    """

    if retention_days < 1:
        raise ValueError("retention_days must be positive")
    cutoff = now - timedelta(days=retention_days)
    # The retention contract is per user and endpoint.  key_id remains in the
    # row schema for account adapters that need it, but it must not create a
    # second retention bucket for a user who rotated keys.
    buckets: dict[tuple[date, str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    retained: list[UsageMetadata] = []
    for item in records:
        if item.timestamp < cutoff:
            key = (item.timestamp.date(), item.user_id, item.route)
            bucket = buckets[key]
            bucket[0] += 1
            bucket[1] += int(item.status >= 400)
            bucket[2] += item.latency_ms
            bucket[3] += item.response_size
        else:
            retained.append(item)
    rollups = [
        Rollup(
            day=day,
            user_id=user_id,
            key_id=None,
            route=route,
            request_count=values[0],
            error_count=values[1],
            total_latency_ms=values[2],
            total_response_size=values[3],
        )
        for (day, user_id, route), values in sorted(buckets.items())
    ]
    return rollups, retained


def roll_up_store(
    store: UsageMetadataStore,
    *,
    now: datetime,
    retention_days: int = 90,
) -> int:
    """Roll up and delete old usage rows only after rollup persistence succeeds."""

    if retention_days < 1:
        raise ValueError("retention_days must be positive")
    cutoff = now - timedelta(days=retention_days)
    rollups, _ = roll_up_metadata(
        store.iter_usage_before(cutoff), now=now, retention_days=retention_days
    )
    store.upsert_daily_rollups(rollups)
    store.delete_usage_before(cutoff)
    return len(rollups)

