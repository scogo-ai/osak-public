"""SQLAlchemy persistence models for OSAK's canonical dataset.

Nested canonical values are retained as JSON alongside relational identity and
lookup columns.  This keeps source-specific details lossless while preserving
simple, indexed joins for the API.  None of these tables accepts caller asset
inventories; matching inputs are intentionally request-scoped only.
"""

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from osak.core.db import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class VendorRow(Base):
    __tablename__ = "vendors"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    psirt_urls: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cna: Mapped[str | None] = mapped_column(String(256))
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False
    )

    products: Mapped[list["ProductRow"]] = relationship(back_populates="vendor")
    hardware_models: Mapped[list["HardwareModelRow"]] = relationship(back_populates="vendor")
    advisories: Mapped[list["AdvisoryRow"]] = relationship(back_populates="vendor")


class ProductRow(Base):
    __tablename__ = "products"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    vendor_id: Mapped[str] = mapped_column(ForeignKey("vendors.id"), index=True, nullable=False)
    family: Mapped[str] = mapped_column(Text, nullable=False)
    os: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(256), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cpe_prefixes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    csaf_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    vendor_names: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    supported_platforms_by_release: Mapped[dict[str, list[str]]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    vendor: Mapped[VendorRow] = relationship(back_populates="products")
    affected_ranges: Mapped[list["AffectedRangeRow"]] = relationship(back_populates="product")
    hardware_models: Mapped[list["HardwareModelRow"]] = relationship(back_populates="product")


class HardwareModelRow(Base):
    __tablename__ = "hardware_models"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    vendor_id: Mapped[str] = mapped_column(ForeignKey("vendors.id"), index=True, nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True, nullable=False)
    family: Mapped[str] = mapped_column(String(512), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    vendor: Mapped[VendorRow] = relationship(back_populates="hardware_models")
    product: Mapped[ProductRow] = relationship(back_populates="hardware_models")


class AdvisoryRow(Base):
    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    vendor_id: Mapped[str] = mapped_column(ForeignKey("vendors.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(2048), nullable=False)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="unknown")
    cvss: Mapped[float | None] = mapped_column(Float)
    cves: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    urls: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str | None] = mapped_column(String(64))
    revisions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    closed_scopes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    remediation: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    vendor: Mapped[VendorRow] = relationship(back_populates="advisories")
    ranges: Mapped[list["AffectedRangeRow"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan", order_by="AffectedRangeRow.id"
    )
    cve_links: Mapped[list["AdvisoryCVERow"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )


class AdvisoryCVERow(Base):
    __tablename__ = "advisory_cves"

    advisory_id: Mapped[str] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)

    advisory: Mapped[AdvisoryRow] = relationship(back_populates="cve_links")


class AffectedRangeRow(Base):
    __tablename__ = "affected_ranges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), index=True, nullable=False
    )
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True, nullable=False)
    versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    hardware_models: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    default_status: Mapped[str | None] = mapped_column(String(32))
    fixed_versions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    advisory: Mapped[AdvisoryRow] = relationship(back_populates="ranges")
    product: Mapped[ProductRow] = relationship(back_populates="affected_ranges")


class EnrichmentRow(Base):
    __tablename__ = "enrichments"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kev: Mapped[bool | None] = mapped_column(Boolean, index=True)
    kev_date: Mapped[date | None] = mapped_column(Date)
    ransomware: Mapped[str | None] = mapped_column(String(256))
    epss: Mapped[float | None] = mapped_column(Float)
    percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[date | None] = mapped_column(Date)
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    cpes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class EoLRecordRow(Base):
    __tablename__ = "eol_records"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    vendor_id: Mapped[str] = mapped_column(ForeignKey("vendors.id"), index=True, nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True, nullable=False)
    model: Mapped[str | None] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(256))
    eos: Mapped[date | None] = mapped_column(Date)
    end_maintenance: Mapped[date | None] = mapped_column(Date)
    end_security: Mapped[date | None] = mapped_column(Date)
    last_support: Mapped[date | None] = mapped_column(Date)
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class ProvenanceRow(Base):
    __tablename__ = "provenance"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    record_id: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    field: Mapped[str] = mapped_column(String(256), nullable=False, default="*")
    source: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    license: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="high")


class SourceSyncStateRow(Base):
    __tablename__ = "source_sync_states"

    source_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cursor: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    records_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ConflictRow(Base):
    __tablename__ = "conflicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    record_id: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    field: Mapped[str] = mapped_column(String(256), nullable=False)
    winner_source: Mapped[str] = mapped_column(String(256), nullable=False)
    loser_source: Mapped[str] = mapped_column(String(256), nullable=False)
    winning_value: Mapped[Any] = mapped_column(JSON, nullable=False)
    losing_value: Mapped[Any] = mapped_column(JSON, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolution: Mapped[str | None] = mapped_column(String(32))


class ChangeRow(Base):
    __tablename__ = "changes"

    # SQLite only auto-increments a column declared exactly INTEGER PRIMARY KEY;
    # PostgreSQL still gives this column a normal integer sequence in production.
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    record_id: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(256), index=True)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class RawDocumentRow(Base):
    __tablename__ = "raw_documents"

    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str | None] = mapped_column(String(256), index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    media_type: Mapped[str] = mapped_column(String(256), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    observations: Mapped[list["RawObservationRow"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class RawObservationRow(Base):
    __tablename__ = "raw_document_observations"
    __table_args__ = (
        UniqueConstraint(
            "content_hash",
            "source_id",
            "url",
            "fetched_at",
            name="uq_raw_document_observation",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    content_hash: Mapped[str] = mapped_column(
        ForeignKey("raw_documents.content_hash", ondelete="CASCADE"), index=True, nullable=False
    )
    source_id: Mapped[str | None] = mapped_column(String(256), index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    media_type: Mapped[str] = mapped_column(String(256), nullable=False)

    document: Mapped[RawDocumentRow] = relationship(back_populates="observations")


@event.listens_for(RawDocumentRow, "before_update")
def _raw_document_update_is_forbidden(*_: Any) -> None:
    raise ValueError("raw documents are immutable")


@event.listens_for(RawDocumentRow, "before_delete")
def _raw_document_delete_is_forbidden(*_: Any) -> None:
    raise ValueError("raw documents are immutable")


@event.listens_for(RawObservationRow, "before_update")
def _raw_observation_update_is_forbidden(*_: Any) -> None:
    raise ValueError("raw observations are immutable")


@event.listens_for(RawObservationRow, "before_delete")
def _raw_observation_delete_is_forbidden(*_: Any) -> None:
    raise ValueError("raw observations are immutable")


# Friendly aliases for consumers that prefer the domain names over the Row suffix.
VendorRecord = VendorRow
ProductRecord = ProductRow
HardwareModelRecord = HardwareModelRow
AdvisoryRecord = AdvisoryRow
AffectedRangeRecord = AffectedRangeRow
EnrichmentRecord = EnrichmentRow
EoLRecord = EoLRecordRow
