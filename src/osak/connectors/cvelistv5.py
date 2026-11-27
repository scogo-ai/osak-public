"""CVE Program CVE List V5 connector.

The repository is the advisory backbone. A first run streams the official
daily baseline release archive; subsequent runs consume ``deltaLog.json``
inclusively at the persisted cursor. Inclusive replay is deliberate: a worker
that crashes after writing a record but before advancing its cursor cannot
create a gap. Canonical writes are idempotent by advisory/CVE id.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from shutil import copyfileobj
from tempfile import SpooledTemporaryFile
from typing import Any, ClassVar, Literal, cast
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

import httpx

from osak.connectors.base import HealthStatus, RawDocument, SourceLicense
from osak.connectors.common import (
    ConnectorError,
    configured_vendor_scope,
    cve_id,
    document_from_response,
    ensure_utc,
    healthcheck,
    parse_datetime,
    parse_json,
    slug,
    source_headers,
    utc_now,
)
from osak.core.catalog import resolve_product, resolve_vendor
from osak.core.models import (
    Advisory,
    AffectedRange,
    CanonicalRecord,
    Product,
    Provenance,
    Remediation,
    Vendor,
    VersionRange,
)

SeverityValue = Literal["critical", "high", "medium", "low", "unknown"]
RangeStatus = Literal["affected", "not_affected", "fixed", "under_investigation"]
DefaultStatus = Literal["affected", "not_affected"]

_PLACEHOLDER_IDENTITY_VALUES = {
    "n-a",
    "n/a",
    "na",
    "not-applicable",
    "unknown",
    "none",
}


def _bounded_identity(value: str) -> str:
    """Keep deterministic source identities within the canonical id limit."""

    normalized = slug(value)
    if len(normalized) <= 256:
        return normalized
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]
    return f"{normalized[: 256 - len(digest) - 1]}-{digest}"


def _is_placeholder_identity(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().casefold().replace("_", "-").replace(" ", "-")
    return normalized in _PLACEHOLDER_IDENTITY_VALUES

CVE_LIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
CVE_LIST_API = "https://api.github.com/repos/CVEProject/cvelistV5"


class CveListV5Connector:
    id: ClassVar[str] = "cvelistv5"
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "GitHub and raw.githubusercontent.com limits apply"
    schedule: ClassVar[int] = 300
    license: ClassVar[SourceLicense] = SourceLicense(
        name="CVE Program Terms of Use",
        url="https://www.cve.org/Legal/TermsOfUse",
        attribution="CVE Program",
        redistribution="facts",
    )

    releases_url: ClassVar[str] = f"{CVE_LIST_API}/releases?per_page=10"
    delta_url: ClassVar[str] = f"{CVE_LIST_RAW}/cves/deltaLog.json"

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        bootstrap_url: str | None = None,
        bootstrap_path: str | os.PathLike[str] | None = None,
        max_records: int | None = None,
        timeout: float = 60,
    ) -> None:
        self.client = client or httpx.Client(headers=source_headers(), follow_redirects=True)
        self.bootstrap_url = bootstrap_url
        archive = bootstrap_path or os.getenv("OSAK_CVE_BASELINE_ARCHIVE")
        self.bootstrap_path = Path(archive) if archive else None
        self.max_records = max_records
        self.timeout = timeout
        self.scope = configured_vendor_scope()
        self.vendor_scope = sorted(self.scope) if self.scope else ["*"]

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        if since is None:
            yield from self._fetch_full()
        else:
            yield from self._fetch_delta(ensure_utc(since))

    def accepts_document(
        self,
        raw: RawDocument,
        *,
        has_advisory: Callable[[str], bool] | None = None,
    ) -> bool:
        """Keep matching vendor records and corrections to previously stored CVEs."""
        if self.scope is None:
            return True
        payload = parse_json(raw)
        if not isinstance(payload, dict):
            raise ConnectorError("CVE source response is not a record")
        metadata = payload.get("cveMetadata")
        identifier = cve_id(metadata.get("cveId")) if isinstance(metadata, dict) else None
        containers = payload.get("containers")
        if isinstance(metadata, dict) and self._scoped_vendor(metadata.get("assignerShortName")):
            return True
        if isinstance(containers, dict):
            cna = containers.get("cna")
            if isinstance(cna, dict):
                issuer = cna.get("providerMetadata")
                if isinstance(issuer, dict) and self._scoped_vendor(issuer.get("shortName")):
                    return True
            adp = containers.get("adp")
            providers = [cna, *(adp if isinstance(adp, list) else [])]
            for provider in providers:
                affected = provider.get("affected") if isinstance(provider, dict) else None
                if isinstance(affected, list) and any(
                    isinstance(item, dict) and self._scoped_vendor(item.get("vendor"))
                    for item in affected
                ):
                    return True
        return bool(has_advisory is not None and identifier and has_advisory(identifier))

    def _scoped_vendor(self, value: Any) -> bool:
        vendor = resolve_vendor(value) if isinstance(value, str) else None
        return bool(vendor is not None and self.scope is not None and vendor.id in self.scope)

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = parse_json(raw)
        if not isinstance(payload, dict):
            raise ConnectorError(f"{raw.url} did not contain a CVE record object")
        metadata = payload.get("cveMetadata")
        if not isinstance(metadata, dict):
            return
        identifier = cve_id(metadata.get("cveId"))
        if identifier is None:
            return
        containers = payload.get("containers")
        if not isinstance(containers, dict):
            return
        cna = containers.get("cna")
        if not isinstance(cna, dict):
            return
        assigner = (
            metadata.get("assignerShortName")
            or (cna.get("providerMetadata") or {}).get("shortName")
            or "unknown"
        )
        assigner_name = str(assigner)
        assigner_vendor = self._vendor_for_name(assigner_name, raw)
        vendor_id = assigner_vendor.id
        title = cna.get("title")
        if not isinstance(title, str) or not title.strip():
            title = identifier
        metrics = self._metrics(cna)
        references = self._references(cna.get("references"), identifier)
        ranges, products, vendors = self._ranges(containers, identifier, assigner_name, raw)
        if vendor_id == "arista" and any(p.id == "arista-eos" for p in products):
            fixes = list(self._eos_fixed_ranges(cna, identifier, raw))
            for affected in ranges:
                if affected.product_id != "arista-eos" or affected.status != "affected":
                    continue
                boundary = affected.versions.lower or affected.versions.exact
                for fix in fixes:
                    if boundary and boundary.startswith(f"{fix.versions.train}."):
                        affected.fixed_versions.extend(fix.fixed_versions)
            ranges.extend(fixes)
        if not _is_placeholder_identity(assigner_name) and all(
            vendor.id != assigner_vendor.id for vendor in vendors
        ):
            vendors.insert(0, assigner_vendor)
        provenance = [self._provenance(raw, field="advisory")]
        remediation = self._remediation(cna)
        yield from vendors
        yield from products
        yield Advisory(
            id=identifier,
            vendor_id=vendor_id,
            title=title.strip(),
            published=parse_datetime(metadata.get("datePublished")),
            updated=parse_datetime(metadata.get("dateUpdated")),
            severity=self._severity(metrics),
            cvss=metrics[0][0] if metrics else None,
            cves=[identifier],
            urls=references,
            status=str(metadata.get("state")).lower() if metadata.get("state") else None,
            ranges=ranges,
            remediation=remediation,
            provenance=provenance,
        )

    def healthcheck(self) -> HealthStatus:
        return healthcheck(self.client, self.delta_url)

    def document_from_response(
        self,
        response: httpx.Response,
        *,
        url: str | None = None,
        fetched_at: datetime | None = None,
    ) -> RawDocument:
        return document_from_response(response, url=url, fetched_at=fetched_at)

    def _fetch_full(self) -> Iterator[RawDocument]:
        archive_url, published_at = (
            (self.bootstrap_url, None)
            if self.bootstrap_url
            else self._latest_baseline_info()
        )
        fetched_at = published_at or utc_now()
        if self.bootstrap_path is not None:
            self.bootstrap_path.parent.mkdir(parents=True, exist_ok=True)
            metadata_path = self.bootstrap_path.with_name(f"{self.bootstrap_path.name}.json")
            cached_url, cached_fetched_at = self._read_archive_metadata(metadata_path)
            # Hourly releases can link to the same immutable midnight snapshot.
            cache_current = (
                self.bootstrap_path.exists()
                and cached_url is not None
                and cached_fetched_at is not None
                and (
                    cached_url == archive_url
                    or (
                        cached_fetched_at == published_at
                        and Path(urlparse(cached_url).path).name == Path(urlparse(archive_url).path).name
                    )
                )
            )
            if self.bootstrap_url and self.bootstrap_path.exists() and cached_url is None:
                # A caller-supplied bootstrap URL plus an existing local path
                # is an explicit fixture/archive input, not an implicit cache.
                cache_current = True
                fetched_at = utc_now()
            if not cache_current:
                partial = self.bootstrap_path.with_name(f".{self.bootstrap_path.name}.partial")
                try:
                    with self.client.stream(
                        "GET", archive_url, headers=source_headers(), timeout=self.timeout
                    ) as response, partial.open("wb") as destination:
                        response.raise_for_status()
                        for chunk in response.iter_bytes():
                            destination.write(chunk)
                        destination.flush()
                        os.fsync(destination.fileno())
                    os.replace(partial, self.bootstrap_path)
                    metadata_partial = metadata_path.with_name(f".{metadata_path.name}.partial")
                    with metadata_partial.open("w", encoding="utf-8") as metadata_file:
                        json.dump(
                            {
                                "archive_url": archive_url,
                                "fetched_at": fetched_at.isoformat(),
                            },
                            metadata_file,
                            sort_keys=True,
                        )
                        metadata_file.write("\n")
                        metadata_file.flush()
                        os.fsync(metadata_file.fileno())
                    os.replace(metadata_partial, metadata_path)
                except BaseException:
                    partial.unlink(missing_ok=True)
                    metadata_path.with_name(f".{metadata_path.name}.partial").unlink(
                        missing_ok=True
                    )
                    raise
            elif cached_url is not None and cached_fetched_at is not None:
                archive_url = cached_url
                fetched_at = cached_fetched_at
            with self.bootstrap_path.open("rb") as archive_file:
                yield from self._iter_archive(archive_file, archive_url, fetched_at)
            return
        with self.client.stream("GET", archive_url, headers=source_headers(), timeout=self.timeout) as response:
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise ConnectorError(f"CVE List V5 baseline returned HTTP {response.status_code}") from exc
            with SpooledTemporaryFile(max_size=16 * 1024 * 1024) as archive_file:
                for chunk in response.iter_bytes():
                    archive_file.write(chunk)
                archive_file.seek(0)
                yield from self._iter_archive(archive_file, archive_url, fetched_at)

    def _iter_archive(
        self, archive_file: Any, archive_url: str, fetched_at: datetime
    ) -> Iterator[RawDocument]:
        try:
            with ZipFile(archive_file) as archive:
                count = 0
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    if not self._is_cve_path(member.filename):
                        # New CVE releases wrap the actual record archive in a
                        # top-level ``cves.zip`` member. Stream that nested
                        # archive without materializing it in memory.
                        if not member.filename.endswith(".zip"):
                            continue
                        with archive.open(member) as nested_stream, SpooledTemporaryFile(
                            max_size=16 * 1024 * 1024
                        ) as nested_file:
                            copyfileobj(nested_stream, nested_file)
                            nested_file.seek(0)
                            with ZipFile(nested_file) as nested_archive:
                                for nested_member in nested_archive.infolist():
                                    if nested_member.is_dir() or not self._is_cve_path(
                                        nested_member.filename
                                    ):
                                        continue
                                    if self.max_records is not None and count >= self.max_records:
                                        break
                                    content = nested_archive.read(nested_member)
                                    yield RawDocument(
                                        url=(
                                            f"{archive_url}#{member.filename}"
                                            f"#{nested_member.filename}"
                                        ),
                                        fetched_at=fetched_at,
                                        content=content,
                                        media_type="application/json",
                                    )
                                    count += 1
                        continue
                    if self.max_records is not None and count >= self.max_records:
                        break
                    content = archive.read(member)
                    yield RawDocument(
                        url=f"{archive_url}#{member.filename}",
                        fetched_at=fetched_at,
                        content=content,
                        media_type="application/json",
                    )
                    count += 1
                if count == 0:
                    raise ConnectorError("CVE List V5 baseline contained no CVE documents")
        except BadZipFile as exc:
            raise ConnectorError("CVE List V5 baseline was not a ZIP archive") from exc

    @staticmethod
    def _read_archive_metadata(path: Path) -> tuple[str | None, datetime | None]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None, None
        if not isinstance(payload, dict):
            return None, None
        archive_url = payload.get("archive_url")
        fetched_at_value = payload.get("fetched_at")
        if not isinstance(archive_url, str) or not isinstance(fetched_at_value, str):
            return None, None
        fetched_at = parse_datetime(fetched_at_value)
        return archive_url, fetched_at

    def _latest_baseline_info(self) -> tuple[str, datetime | None]:
        payload = self._get_json(self.releases_url)
        releases = payload if isinstance(payload, list) else [payload]
        for release in releases:
            if not isinstance(release, dict):
                continue
            assets = release.get("assets")
            if not isinstance(assets, list):
                continue
            for asset in assets:
                if not isinstance(asset, dict):
                    continue
                name = str(asset.get("name", ""))
                link = asset.get("browser_download_url")
                dated_archive = re.fullmatch(
                    r"(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip(?:\.zip)?", name
                )
                if not dated_archive or not isinstance(link, str):
                    continue
                parsed = urlparse(link)
                if (
                    parsed.scheme == "https"
                    and parsed.netloc == "github.com"
                    and parsed.path.startswith("/CVEProject/cvelistV5/releases/download/")
                ):
                    # Hourly releases reattach the midnight archive. Using
                    # the release upload time would skip the intervening deltas.
                    snapshot_at = parse_datetime(f"{dated_archive[1]}T00:00:00Z")
                    if snapshot_at is not None:
                        return link, snapshot_at
        raise ConnectorError("CVE List V5 did not publish a daily baseline archive")

    def _latest_baseline_url(self) -> str:
        return self._latest_baseline_info()[0]

    def _fetch_delta(self, since: datetime) -> Iterator[RawDocument]:
        delta_response = self.client.get(
            self.delta_url, headers=source_headers(), timeout=self.timeout
        )
        delta_document = self.document_from_response(delta_response, url=self.delta_url)
        payload = parse_json(delta_document)
        if isinstance(payload, dict):
            payload = payload.get("changes", [])
        if not isinstance(payload, list):
            raise ConnectorError("CVE List V5 deltaLog.json is not a list")

        selected: dict[str, tuple[datetime, str]] = {}
        errors = 0
        for batch in payload:
            if not isinstance(batch, dict):
                continue
            fetched = parse_datetime(batch.get("fetchTime"))
            if fetched is None or fetched < since:
                continue
            batch_errors = batch.get("error")
            if isinstance(batch_errors, list):
                errors += len(batch_errors)
            for category in ("new", "updated"):
                changes = batch.get(category)
                if not isinstance(changes, list):
                    continue
                for change in changes:
                    if not isinstance(change, dict):
                        continue
                    identifier = cve_id(change.get("cveId"))
                    link = self._publisher_link(change.get("githubLink"))
                    if identifier is None or link is None:
                        continue
                    previous = selected.get(identifier)
                    if previous is None or fetched >= previous[0]:
                        selected[identifier] = (fetched, link)
        if errors:
            raise ConnectorError(f"CVE List V5 delta log reported {errors} error(s)")

        timestamps = [
            parsed
            for batch in payload
            if isinstance(batch, dict)
            for parsed in [parse_datetime(batch.get("fetchTime"))]
            if parsed is not None
        ]
        if not timestamps or since < min(timestamps):
            # deltaLog currently retains about one month.  A cursor older than
            # that window must not be treated as an empty update; rebuild from
            # the official daily baseline so no records are skipped.
            yield from self._fetch_full()
            return

        for fetched, link in selected.values():
            response = self.client.get(link, headers=source_headers(), timeout=self.timeout)
            # The worker persists the latest raw ``fetched_at`` as its source
            # cursor. Preserve the delta publisher's fetchTime rather than
            # advancing the cursor to local wall-clock time after a download.
            yield self.document_from_response(response, url=link, fetched_at=fetched)

    def _get_json(self, url: str) -> Any:
        response = self.client.get(url, headers=source_headers(), timeout=self.timeout)
        document = self.document_from_response(response, url=url)
        return parse_json(document)

    @staticmethod
    def _publisher_link(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        parsed = urlparse(value)
        if (
            parsed.scheme == "https"
            and parsed.netloc == "raw.githubusercontent.com"
            and parsed.path.startswith("/CVEProject/cvelistV5/main/cves/")
            and CveListV5Connector._is_cve_path(parsed.path)
            and not parsed.query
            and not parsed.fragment
        ):
            return value
        return None

    @staticmethod
    def _is_cve_path(path: str) -> bool:
        return path.endswith(".json") and cve_id(path.rsplit("/", 1)[-1][:-5]) is not None

    @staticmethod
    def _metrics(container: dict[str, Any]) -> list[tuple[float, str]]:
        values: list[tuple[float, str]] = []
        metrics = container.get("metrics")
        if not isinstance(metrics, list):
            return values
        preferred = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV2")
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for name in preferred:
                data = metric.get(name)
                if not isinstance(data, dict):
                    continue
                score = data.get("baseScore")
                severity = data.get("baseSeverity")
                if isinstance(score, (int, float)) and 0 <= score <= 10:
                    values.append((float(score), str(severity).lower() if severity else "unknown"))
                    break
        return values

    @staticmethod
    def _severity(metrics: list[tuple[float, str]]) -> SeverityValue:
        allowed = {"critical", "high", "medium", "low"}
        for _, severity in metrics:
            if severity in allowed:
                return cast(SeverityValue, severity)
        return "unknown"

    def _references(self, values: Any, identifier: str) -> list[str]:
        if not isinstance(values, list):
            values = []
        references: list[str] = []
        for reference in values:
            if not isinstance(reference, dict) or not isinstance(reference.get("url"), str):
                continue
            url = reference["url"].strip()
            tags = {str(tag).lower() for tag in reference.get("tags", []) if isinstance(tag, str)}
            label = str(reference.get("name", "")).lower()
            if tags & {"exploit", "poc", "proof-of-concept", "payload"}:
                continue
            if any(token in label for token in ("exploit", "poc", "payload")):
                continue
            if tags & {"vendor-advisory", "vdb-entry", "security-advisory", "advisory"}:
                references.append(url)
                continue
            if "cve.org" in url.lower() or any(
                token in label for token in ("advisory", "cisco-sa-", "fg-ir-", "arista-sa")
            ) or any(
                token in url.lower()
                for token in ("/security-advisory", "securityadvisory", "/psirt/")
            ):
                references.append(url)
        if not references:
            references.append(f"https://www.cve.org/CVERecord?id={identifier}")
        return list(dict.fromkeys(references))

    def _ranges(
        self,
        containers: dict[str, Any],
        identifier: str,
        assigner_name: str,
        raw: RawDocument,
    ) -> tuple[list[AffectedRange], list[Product], list[Vendor]]:
        ranges: list[AffectedRange] = []
        products: list[Product] = []
        vendors: list[Vendor] = []
        seen: set[tuple[str, str, str, str | None, str | None, DefaultStatus | None]] = set()
        seen_products: set[str] = set()
        seen_vendors: set[str] = set()
        for container_name, container in containers.items():
            if container_name != "cna" and container_name != "adp":
                continue
            candidates = [container] if isinstance(container, dict) else []
            if container_name == "adp" and isinstance(container, list):
                candidates = [entry for entry in container if isinstance(entry, dict)]
            for candidate in candidates:
                affected = candidate.get("affected") if isinstance(candidate, dict) else None
                if not isinstance(affected, list):
                    continue
                for item in affected:
                    if not isinstance(item, dict):
                        continue
                    product = item.get("product") or item.get("packageName") or "unknown"
                    package = item.get("packageName")
                    vendor_name = item.get("vendor")
                    if not isinstance(vendor_name, str) or not vendor_name.strip():
                        vendor_name = assigner_name
                    unresolved_vendor = _is_placeholder_identity(vendor_name)
                    unresolved_product = _is_placeholder_identity(str(product)) and not (
                        isinstance(package, str) and not _is_placeholder_identity(package)
                    )
                    if unresolved_product:
                        continue
                    identity_vendor_name = assigner_name if unresolved_vendor else vendor_name
                    lookup_product = resolve_product(identity_vendor_name, str(product))
                    if lookup_product is None and isinstance(package, str):
                        lookup_product = resolve_product(identity_vendor_name, package)
                    if unresolved_vendor and lookup_product is None:
                        continue
                    vendor_record = self._vendor_for_name(identity_vendor_name, raw)
                    product_record = self._product_for_item(
                        identity_vendor_name,
                        str(product),
                        str(package) if isinstance(package, str) else None,
                        raw,
                    )
                    if unresolved_vendor and product_record.scheme == "unknown":
                        # Keep the CVE/advisory, but do not create placeholder
                        # catalog identities or applicability that could be
                        # mistaken for a real product match.
                        continue
                    product_id = product_record.id
                    if not unresolved_vendor and vendor_record.id not in seen_vendors:
                        vendors.append(vendor_record)
                        seen_vendors.add(vendor_record.id)
                    if product_id not in seen_products:
                        products.append(product_record)
                        seen_products.add(product_id)
                    product_vendor = resolve_vendor(product_record.vendor_id)
                    if product_vendor is not None and all(
                        vendor.id != product_vendor.id for vendor in vendors
                    ):
                        vendors.append(
                            product_vendor.model_copy(
                                update={"provenance": [self._provenance(raw, field="vendor")]}
                            )
                        )
                    default_status = self._default_status(item.get("defaultStatus"))
                    entries = item.get("versions")
                    if not isinstance(entries, list) or not entries:
                        status = default_status or self._status(item.get("status"))
                        if status is not None:
                            ranges.append(
                                self._make_range(
                                    identifier,
                                    product_id,
                                    VersionRange(),
                                    status,
                                    [],
                                    raw,
                                    default_status=default_status,
                                )
                            )
                        continue
                    for version_entry in entries:
                        if not isinstance(version_entry, dict):
                            continue
                        status = self._status(version_entry.get("status"))
                        if status is None and version_entry.get("status") is None:
                            status = default_status or self._status(item.get("status"))
                        if status is None:
                            status = "under_investigation"
                        bounds = self._version_range(version_entry)
                        if bounds is None:
                            # Keep an unparseable publisher exception as an
                            # explicit under-investigation range. Dropping it
                            # would let defaultStatus incorrectly clear an
                            # asset when the exception could not be evaluated.
                            raw_version = version_entry.get("version")
                            bounds = VersionRange(
                                exact=str(raw_version)
                                if isinstance(raw_version, str) and raw_version.strip()
                                else None
                            )
                            status = "under_investigation"
                        fixed: list[str] = []
                        version = version_entry.get("version")
                        if status in {"fixed", "not_affected"} and self._usable_version(version):
                            fixed.append(str(version))
                        key = (
                            product_id,
                            status,
                            str(bounds.exact),
                            bounds.lower,
                            bounds.upper,
                            default_status,
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        ranges.append(
                            self._make_range(
                                identifier,
                                product_id,
                                bounds,
                                status,
                                fixed,
                                raw,
                                default_status=default_status,
                            )
                        )
        return ranges, products, vendors

    def _vendor_for_name(self, name: str, raw: RawDocument) -> Vendor:
        resolved = resolve_vendor(name)
        provenance = [self._provenance(raw, field="vendor")]
        if resolved is not None:
            return resolved.model_copy(update={"provenance": provenance})
        return Vendor(
            id=_bounded_identity(name),
            name=name.strip() or "Unknown",
            provenance=provenance,
        )

    def _product_for_item(
        self,
        vendor_name: str,
        product_name: str,
        package_name: str | None,
        raw: RawDocument,
    ) -> Product:
        resolved = resolve_product(vendor_name, product_name)
        if resolved is None and package_name:
            resolved = resolve_product(vendor_name, package_name)
        provenance = [self._provenance(raw, field="product")]
        if resolved is not None:
            aliases = list(
                dict.fromkeys(
                    [*resolved.aliases, product_name, *([package_name] if package_name else [])]
                )
            )
            return resolved.model_copy(
                update={
                    "aliases": aliases,
                    "vendor_names": list(dict.fromkeys([*resolved.vendor_names, vendor_name])),
                    "provenance": provenance,
                }
            )
        vendor = resolve_vendor(vendor_name)
        vendor_id = vendor.id if vendor is not None else slug(vendor_name)
        short_name = product_name
        if package_name and package_name.casefold() != product_name.casefold():
            short_name = f"{product_name}-{package_name}"
        return Product(
            id=_bounded_identity(f"{vendor_id}-{short_name}"),
            vendor_id=vendor_id,
            family=product_name,
            os=package_name or product_name,
            scheme="unknown",
            aliases=[package_name] if package_name else [],
            vendor_names=[vendor_name],
            provenance=provenance,
        )

    @staticmethod
    def _status(value: Any) -> RangeStatus | None:
        if not isinstance(value, str):
            return None
        value = value.lower().strip()
        if value == "affected":
            return "affected"
        if value in {"unaffected", "not_affected"}:
            return "not_affected"
        if value == "fixed":
            return "fixed"
        if value in {"unknown", "under_investigation"}:
            return "under_investigation"
        return None

    @staticmethod
    def _default_status(value: Any) -> DefaultStatus | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        if normalized == "affected":
            return "affected"
        if normalized in {"unaffected", "not_affected"}:
            return "not_affected"
        return None

    @classmethod
    def _version_range(cls, entry: dict[str, Any]) -> VersionRange | None:
        version = entry.get("version")
        lower = entry.get("greaterThanOrEqual")
        include_lower = True
        if lower is None:
            greater_than = entry.get("greaterThan")
            if greater_than is not None:
                lower = greater_than
                include_lower = False
        if lower is None and cls._usable_version(version) and not any(
            key in entry for key in ("lessThan", "lessThanOrEqual")
        ):
            lower = None
        upper = entry.get("lessThanOrEqual")
        include_upper = True
        if upper is None:
            less_than = entry.get("lessThan")
            if less_than is not None:
                upper = less_than
                include_upper = False
        if isinstance(lower, str) and lower in {"*", "N/A", "n/a", "0"}:
            lower = None
        if isinstance(upper, str) and upper == "*":
            upper = None
        if lower is None and upper is None and isinstance(version, str):
            endpoints = version.split()
            if len(endpoints) == 2 and all(cls._usable_version(endpoint) for endpoint in endpoints):
                return VersionRange(
                    lower=endpoints[0],
                    upper=endpoints[1],
                    include_lower=True,
                    include_upper=True,
                )
        if lower is None and upper is not None and cls._usable_version(version):
            lower = str(version)
            include_lower = True
        exact = None
        if cls._usable_version(version) and lower is None and upper is None:
            exact = str(version)
        if lower is None and upper is None and exact is None:
            # The CVE schema allows an unbounded affected item through
            # ``defaultStatus``; a placeholder version by itself is not
            # evidence for a concrete version.
            return None
        return VersionRange(
            lower=str(lower) if lower is not None else None,
            upper=str(upper) if upper is not None else None,
            include_lower=include_lower,
            include_upper=include_upper,
            exact=exact,
        )

    @staticmethod
    def _usable_version(value: Any) -> bool:
        return (
            isinstance(value, str)
            and bool(value.strip())
            and not any(character.isspace() for character in value)
            and any(character.isdigit() for character in value)
            and value not in {"0", "*", "N/A", "n/a"}
        )

    def _make_range(
        self,
        identifier: str,
        product_id: str,
        versions: VersionRange,
        status: RangeStatus,
        fixed: list[str],
        raw: RawDocument,
        *,
        default_status: DefaultStatus | None = None,
    ) -> AffectedRange:
        return AffectedRange(
            advisory_id=identifier,
            product_id=product_id,
            versions=versions,
            status=status,
            default_status=default_status,
            fixed_versions=fixed,
            provenance=[self._provenance(raw, field="affected")],
        )

    def _eos_fixed_ranges(
        self, cna: dict[str, Any], identifier: str, raw: RawDocument
    ) -> Iterator[AffectedRange]:
        # Arista CNA solution tables identify a release and train on each row.
        # Ignore other sections, including conditional hotfix instructions.
        heading = f"{identifier} has been fixed in the following releases:"
        row = re.compile(
            r"^[ \t]*(?:-\s*)?(?P<version>(?P<train>\d+\.\d+)\.\d+(?:\.\d+)?[FM]?)"
            r" and later releases in the (?P=train)\.x train[ \t]*$", re.IGNORECASE,
        )
        for solution in cna.get("solutions", []):
            if not isinstance(solution, dict) or not isinstance(solution.get("value"), str):
                continue
            _, found, body = solution["value"].partition(heading)
            if not found:
                continue
            for line in body.strip().splitlines():
                matched = row.fullmatch(line)
                if not matched:
                    break
                fixed = matched.group("version")
                yield AffectedRange(
                    advisory_id=identifier, product_id="arista-eos",
                    versions=VersionRange(train=matched.group("train"), lower=fixed),
                    status="fixed", fixed_versions=[fixed],
                    provenance=[self._provenance(raw, field="containers.cna.solutions")],
                )

    def _remediation(self, cna: dict[str, Any]) -> Remediation | None:
        solutions = cna.get("solutions")
        if not isinstance(solutions, list):
            return None
        targets: list[str] = []
        urls: list[str] = []
        for solution in solutions:
            if not isinstance(solution, dict):
                continue
            product_ids = solution.get("product_ids")
            if isinstance(product_ids, list):
                targets.extend(str(value) for value in product_ids if isinstance(value, str))
            value = solution.get("value")
            if isinstance(value, str) and value.startswith(("https://", "http://")):
                urls.append(value)
        if not targets and not urls:
            return None
        return Remediation(targets=list(dict.fromkeys(targets)), url=next(iter(dict.fromkeys(urls)), None))

    def _provenance(self, raw: RawDocument, *, field: str) -> Provenance:
        return Provenance(
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license=self.license.name,
            field=field,
        )


CVEListV5Connector = CveListV5Connector
