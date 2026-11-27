"""Create OSAK canonical dataset and ingestion bookkeeping tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_core_schema"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vendors",
        sa.Column("id", sa.String(length=256), primary_key=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("psirt_urls", sa.JSON(), nullable=False),
        sa.Column("cna", sa.String(length=256)),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "products",
        sa.Column("id", sa.String(length=256), primary_key=True),
        sa.Column("vendor_id", sa.String(length=256), sa.ForeignKey("vendors.id"), nullable=False),
        sa.Column("family", sa.String(length=512), nullable=False),
        sa.Column("os", sa.String(length=256), nullable=False),
        sa.Column("scheme", sa.String(length=256), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("cpe_prefixes", sa.JSON(), nullable=False),
        sa.Column("csaf_ids", sa.JSON(), nullable=False),
        sa.Column("vendor_names", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_products_vendor_id", "products", ["vendor_id"])
    op.create_table(
        "hardware_models",
        sa.Column("id", sa.String(length=256), primary_key=True),
        sa.Column("vendor_id", sa.String(length=256), sa.ForeignKey("vendors.id"), nullable=False),
        sa.Column(
            "product_id", sa.String(length=256), sa.ForeignKey("products.id"), nullable=False
        ),
        sa.Column("family", sa.String(length=512), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_hardware_models_vendor_id", "hardware_models", ["vendor_id"])
    op.create_index("ix_hardware_models_product_id", "hardware_models", ["product_id"])
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(length=256), primary_key=True),
        sa.Column("vendor_id", sa.String(length=256), sa.ForeignKey("vendors.id"), nullable=False),
        sa.Column("title", sa.String(length=2048), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True)),
        sa.Column("updated", sa.DateTime(timezone=True)),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("cvss", sa.Float()),
        sa.Column("cves", sa.JSON(), nullable=False),
        sa.Column("urls", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=64)),
        sa.Column("revisions", sa.JSON(), nullable=False),
        sa.Column("remediation", sa.JSON()),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_advisories_vendor_id", "advisories", ["vendor_id"])
    op.create_index("ix_advisories_published", "advisories", ["published"])
    op.create_index("ix_advisories_updated", "advisories", ["updated"])
    op.create_index("ix_advisories_severity", "advisories", ["severity"])
    op.create_table(
        "advisory_cves",
        sa.Column(
            "advisory_id",
            sa.String(length=256),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("cve_id", sa.String(length=64), primary_key=True),
    )
    op.create_index("ix_advisory_cves_cve_id", "advisory_cves", ["cve_id"])
    op.create_table(
        "affected_ranges",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "advisory_id",
            sa.String(length=256),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "product_id", sa.String(length=256), sa.ForeignKey("products.id"), nullable=False
        ),
        sa.Column("versions", sa.JSON(), nullable=False),
        sa.Column("hardware_models", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("fixed_versions", sa.JSON(), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_affected_ranges_advisory_id", "affected_ranges", ["advisory_id"])
    op.create_index("ix_affected_ranges_product_id", "affected_ranges", ["product_id"])
    op.create_table(
        "enrichments",
        sa.Column("cve_id", sa.String(length=64), primary_key=True),
        sa.Column("kev", sa.Boolean()),
        sa.Column("kev_date", sa.Date()),
        sa.Column("ransomware", sa.String(length=256)),
        sa.Column("epss", sa.Float()),
        sa.Column("percentile", sa.Float()),
        sa.Column("epss_date", sa.Date()),
        sa.Column("cvss", sa.Float()),
        sa.Column("cvss_version", sa.String(length=16)),
        sa.Column("cpes", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_enrichments_kev", "enrichments", ["kev"])
    op.create_table(
        "eol_records",
        sa.Column("id", sa.String(length=256), primary_key=True),
        sa.Column("vendor_id", sa.String(length=256), sa.ForeignKey("vendors.id"), nullable=False),
        sa.Column(
            "product_id", sa.String(length=256), sa.ForeignKey("products.id"), nullable=False
        ),
        sa.Column("model", sa.String(length=256)),
        sa.Column("version", sa.String(length=256)),
        sa.Column("eos", sa.Date()),
        sa.Column("end_maintenance", sa.Date()),
        sa.Column("end_security", sa.Date()),
        sa.Column("last_support", sa.Date()),
        sa.Column("provenance", sa.JSON(), nullable=False),
    )
    op.create_index("ix_eol_records_vendor_id", "eol_records", ["vendor_id"])
    op.create_index("ix_eol_records_product_id", "eol_records", ["product_id"])
    op.create_table(
        "provenance",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("record_type", sa.String(length=64), nullable=False),
        sa.Column("record_id", sa.String(length=256), nullable=False),
        sa.Column("field", sa.String(length=256), nullable=False),
        sa.Column("source", sa.String(length=256), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("license", sa.String(length=512), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
    )
    op.create_index("ix_provenance_record_type", "provenance", ["record_type"])
    op.create_index("ix_provenance_record_id", "provenance", ["record_id"])
    op.create_index("ix_provenance_source", "provenance", ["source"])
    op.create_table(
        "source_sync_states",
        sa.Column("source_id", sa.String(length=256), primary_key=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("cursor", sa.Text()),
        sa.Column("error", sa.Text()),
        sa.Column("records_seen", sa.Integer(), nullable=False),
        sa.Column("records_written", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_table(
        "conflicts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("record_type", sa.String(length=64), nullable=False),
        sa.Column("record_id", sa.String(length=256), nullable=False),
        sa.Column("field", sa.String(length=256), nullable=False),
        sa.Column("winner_source", sa.String(length=256), nullable=False),
        sa.Column("loser_source", sa.String(length=256), nullable=False),
        sa.Column("winning_value", sa.JSON(), nullable=False),
        sa.Column("losing_value", sa.JSON(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolution", sa.String(length=32)),
    )
    op.create_index("ix_conflicts_record_type", "conflicts", ["record_type"])
    op.create_index("ix_conflicts_record_id", "conflicts", ["record_id"])
    op.create_table(
        "changes",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("record_type", sa.String(length=64), nullable=False),
        sa.Column("record_id", sa.String(length=256), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=256)),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON()),
    )
    op.create_index("ix_changes_record_type", "changes", ["record_type"])
    op.create_index("ix_changes_record_id", "changes", ["record_id"])
    op.create_index("ix_changes_source_id", "changes", ["source_id"])
    op.create_index("ix_changes_changed_at", "changes", ["changed_at"])
    op.create_table(
        "raw_documents",
        sa.Column("content_hash", sa.String(length=64), primary_key=True),
        sa.Column("source_id", sa.String(length=256)),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("media_type", sa.String(length=256), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
    )
    op.create_index("ix_raw_documents_source_id", "raw_documents", ["source_id"])
    op.create_table(
        "raw_document_observations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "content_hash",
            sa.String(length=64),
            sa.ForeignKey("raw_documents.content_hash", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_id", sa.String(length=256)),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("media_type", sa.String(length=256), nullable=False),
        sa.UniqueConstraint(
            "content_hash", "source_id", "url", "fetched_at", name="uq_raw_document_observation"
        ),
    )
    op.create_index(
        "ix_raw_document_observations_content_hash", "raw_document_observations", ["content_hash"]
    )
    op.create_index(
        "ix_raw_document_observations_source_id", "raw_document_observations", ["source_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_raw_document_observations_source_id", table_name="raw_document_observations")
    op.drop_index(
        "ix_raw_document_observations_content_hash", table_name="raw_document_observations"
    )
    op.drop_table("raw_document_observations")
    op.drop_index("ix_raw_documents_source_id", table_name="raw_documents")
    op.drop_table("raw_documents")
    op.drop_index("ix_changes_changed_at", table_name="changes")
    op.drop_index("ix_changes_source_id", table_name="changes")
    op.drop_index("ix_changes_record_id", table_name="changes")
    op.drop_index("ix_changes_record_type", table_name="changes")
    op.drop_table("changes")
    op.drop_index("ix_conflicts_record_id", table_name="conflicts")
    op.drop_index("ix_conflicts_record_type", table_name="conflicts")
    op.drop_table("conflicts")
    op.drop_table("source_sync_states")
    op.drop_index("ix_provenance_source", table_name="provenance")
    op.drop_index("ix_provenance_record_id", table_name="provenance")
    op.drop_index("ix_provenance_record_type", table_name="provenance")
    op.drop_table("provenance")
    op.drop_index("ix_eol_records_product_id", table_name="eol_records")
    op.drop_index("ix_eol_records_vendor_id", table_name="eol_records")
    op.drop_table("eol_records")
    op.drop_index("ix_enrichments_kev", table_name="enrichments")
    op.drop_table("enrichments")
    op.drop_index("ix_affected_ranges_product_id", table_name="affected_ranges")
    op.drop_index("ix_affected_ranges_advisory_id", table_name="affected_ranges")
    op.drop_table("affected_ranges")
    op.drop_index("ix_advisory_cves_cve_id", table_name="advisory_cves")
    op.drop_table("advisory_cves")
    op.drop_index("ix_advisories_severity", table_name="advisories")
    op.drop_index("ix_advisories_updated", table_name="advisories")
    op.drop_index("ix_advisories_published", table_name="advisories")
    op.drop_index("ix_advisories_vendor_id", table_name="advisories")
    op.drop_table("advisories")
    op.drop_index("ix_hardware_models_product_id", table_name="hardware_models")
    op.drop_index("ix_hardware_models_vendor_id", table_name="hardware_models")
    op.drop_table("hardware_models")
    op.drop_index("ix_products_vendor_id", table_name="products")
    op.drop_table("products")
    op.drop_table("vendors")
