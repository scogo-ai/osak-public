"""Portable, JSON-serializable contracts shared by ingestion, API and offline matching."""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Verdict = Literal["affected", "not_affected", "unknown"]
Severity = Literal["critical", "high", "medium", "low", "unknown"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Provenance(Model):
    source: Identifier
    fetched_at: AwareDatetime
    url: str
    license: str
    field: str = "*"
    confidence: Literal["high", "medium", "low"] = "high"


class Vendor(Model):
    id: Identifier
    name: str
    aliases: list[str] = []
    psirt_urls: list[str] = []
    cna: str | None = None
    provenance: list[Provenance] = []


class Product(Model):
    id: Identifier
    vendor_id: Identifier
    family: str
    os: str
    scheme: str
    aliases: list[str] = []
    cpe_prefixes: list[str] = []
    csaf_ids: list[str] = []
    vendor_names: list[str] = []
    provenance: list[Provenance] = []
    supported_platforms_by_release: dict[str, list[str]] = {}


class HardwareModel(Model):
    id: Identifier
    vendor_id: Identifier
    product_id: Identifier
    family: str
    aliases: list[str] = []
    provenance: list[Provenance] = []


class Condition(Model):
    feature: str
    required: bool = True
    method: Literal["vendor_structured", "parsed", "llm_extracted"] = "vendor_structured"
    reviewed: bool = False


class VersionRange(Model):
    train: str | None = None
    lower: str | None = None
    upper: str | None = None
    include_lower: bool = True
    include_upper: bool = False
    exact: str | None = None


class AffectedRange(Model):
    advisory_id: Identifier
    product_id: Identifier
    versions: VersionRange
    hardware_models: list[str] = []
    status: Literal["affected", "not_affected", "fixed", "under_investigation"]
    # A publisher's explicit default for versions not covered by the listed
    # ranges. ``None`` means no fallback evidence was published.
    default_status: Literal["affected", "not_affected"] | None = None
    fixed_versions: list[str] = []
    conditions: list[Condition] = []
    provenance: list[Provenance] = []


class Remediation(Model):
    targets: list[str] = []
    workaround: str | None = None
    url: str | None = None
    hotfixes: list[str] = []


class ClosedScopeEvidence(Model):
    """Explicit finite platform scope evidence from a source."""

    vendor_id: Identifier
    product_id: Identifier
    hardware_models: list[Identifier] = Field(min_length=1)
    complete: bool = False
    explicit: bool = False
    provenance: list[Provenance] = []


class Enrichment(Model):
    cve_id: str
    kev: bool | None = None
    kev_date: date | None = None
    ransomware: str | None = None
    epss: float | None = Field(None, ge=0, le=1)
    percentile: float | None = Field(None, ge=0, le=1)
    epss_date: date | None = None
    cvss: float | None = Field(None, ge=0, le=10)
    cvss_version: str | None = None
    cpes: list[str] = []
    provenance: list[Provenance] = []


class Advisory(Model):
    id: Identifier
    vendor_id: Identifier
    title: str
    published: datetime | None = None
    updated: datetime | None = None
    severity: Severity = "unknown"
    cvss: float | None = Field(None, ge=0, le=10)
    cves: list[str] = []
    urls: list[str] = []
    status: str | None = None
    revisions: list[str] = []
    ranges: list[AffectedRange] = []
    closed_scopes: list[ClosedScopeEvidence] = []
    remediation: Remediation | None = None
    provenance: list[Provenance] = []


class EoLRecord(Model):
    id: Identifier
    vendor_id: Identifier
    product_id: Identifier
    model: str | None = None
    version: str | None = None
    eos: date | None = None
    end_maintenance: date | None = None
    end_security: date | None = None
    last_support: date | None = None
    provenance: list[Provenance] = []


CanonicalRecord = Vendor | Product | HardwareModel | Advisory | Enrichment | EoLRecord


class SourceAvailability(Model):
    """Availability metadata used to scope fail-safe matching decisions."""

    source_id: Identifier
    state: str = "unknown"
    kind: Literal["advisory", "enrichment", "eol"] | None = None
    vendor_scope: list[str] = []
    operator_excluded: bool = False


class Dataset(Model):
    vendors: list[Vendor] = []
    products: list[Product] = []
    models: list[HardwareModel] = []
    advisories: list[Advisory] = []
    enrichments: list[Enrichment] = []
    eol: list[EoLRecord] = []
    unavailable_sources: list[str] = []
    source_statuses: list[SourceAvailability] = []


class Asset(Model):
    asset_ref: Identifier
    vendor: Identifier
    version: Identifier
    product: Identifier | None = None
    model: Identifier | None = None
    os: Identifier | None = None
    serial: Identifier | None = None
    features: list[Identifier] | None = Field(None, max_length=128)


class MatchFilters(Model):
    min_severity: Severity | None = None
    kev_only: bool = False


class MatchRequest(Model):
    assets: list[Asset] = Field(min_length=1)
    filters: MatchFilters = Field(default_factory=MatchFilters)


class ConditionResult(Model):
    feature: str
    status: Literal["satisfied", "unsatisfied", "unknown"]


class Priority(Model):
    kev: bool | None = None
    epss: float | None = None
    cvss: float | None = None
    severity: Severity = "unknown"


class Finding(Model):
    advisory_id: str | None
    verdict: Verdict
    confidence: Literal["high", "medium", "low"]
    reasons: list[str]
    conditions: list[ConditionResult] = []
    fixed_versions: list[str] = []
    recommended_target: str | None = None
    workaround: str | None = None
    priority: Priority = Field(default_factory=Priority)
    eol: list[EoLRecord] = []
    provenance: list[Provenance] = []


class AssetResult(Model):
    asset_ref: str
    status: Literal["resolved", "unresolved"]
    product_id: str | None = None
    findings: list[Finding]


class MatchResponse(Model):
    results: list[AssetResult]


class ResolveRequest(Model):
    raw_strings: list[Annotated[str, Field(min_length=1, max_length=2048)]] = Field(
        min_length=1, max_length=500
    )


class Resolution(Model):
    status: Literal["resolved", "unresolved"]
    vendor: str | None = None
    product_id: str | None = None
    version: str | None = None


class ResolveResponse(Model):
    results: list[Resolution]


class SourceSyncState(Model):
    """Operational state for one connector's latest synchronization attempt."""

    source_id: Identifier
    status: Literal["idle", "running", "success", "failed", "disabled"] = "idle"
    last_started_at: AwareDatetime | None = None
    last_attempt_at: AwareDatetime | None = None
    last_success_at: AwareDatetime | None = None
    cursor: str | None = None
    error: str | None = None
    records_seen: int = Field(default=0, ge=0)
    records_written: int = Field(default=0, ge=0)
    metadata: dict[str, object] = {}


class Conflict(Model):
    """A source disagreement retained for review instead of silently discarded."""

    id: int | None = None
    record_type: Identifier
    record_id: Identifier
    field: Identifier
    winner_source: Identifier
    loser_source: Identifier
    winning_value: object
    losing_value: object
    detected_at: AwareDatetime
    resolution: str | None = None


class Change(Model):
    """An append-only canonical dataset change event."""

    sequence: int
    record_type: Identifier
    record_id: Identifier
    operation: Literal["upsert", "delete"]
    source_id: str | None = None
    changed_at: AwareDatetime
    payload: dict[str, object] | None = None


class RawObservation(Model):
    """One source observation of a content-addressed raw document."""

    id: int | None = None
    content_hash: Identifier
    source_id: str | None = None
    url: str
    fetched_at: AwareDatetime
    media_type: str
