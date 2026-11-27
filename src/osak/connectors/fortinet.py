"""Fortinet RSS, CNA normalizer and advisory-page fallback connectors."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx
from bs4 import BeautifulSoup

from osak.connectors.base import HealthStatus, RawDocument
from osak.connectors.oem_common import (
    _FG_IR_RE,
    ConnectorFetchError,
    _as_list,
    _as_mapping,
    _canonical_product_id,
    _catalog_records,
    _cves,
    _HttpConnector,
    _json,
    _license,
    _number,
    _parse_datetime,
    _provenance,
    _safe_url,
    _score_from_metrics,
    _severity_from_score,
    _severity_from_value,
    _sorted_versions,
    _text,
    _train,
    _unique,
    _version_values,
    _xml_items,
)
from osak.core.models import Advisory, AffectedRange, CanonicalRecord, Remediation, VersionRange


class FortinetRssConnector(_HttpConnector):
    id: ClassVar[str] = "fortinet_psirt_rss"
    vendor_scope: ClassVar[list[str]] = ["fortinet"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "15 minute poll; provider-defined"
    schedule: ClassVar[int] = 900
    url: ClassVar[str] = "https://www.fortiguard.com/rss/ir.xml"

    def __init__(
        self,
        *,
        page_fallback_limit: int = 10,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        if page_fallback_limit < 0:
            raise ValueError("page_fallback_limit must not be negative")
        super().__init__(
            allowed_hosts={"www.fortiguard.com", "fortiguard.fortinet.com", "filestore.fortinet.com"},
            timeout=timeout,
            client=client,
        )
        self.page_fallback_limit = page_fallback_limit
        self.license = _license(
            "FortiGuard PSIRT RSS",
            "https://www.fortiguard.com/psirt_policy",
            "Fortinet PSIRT RSS; structured facts and source links only. Review Fortinet terms before redistribution.",
            "restricted",
        )

    @staticmethod
    def severity_from_value(value: Any) -> Literal["critical", "high", "medium", "low", "unknown"]:
        return _severity_from_value(value)

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        del since
        rss = self._get(self.url, headers={"Accept": "application/rss+xml, application/xml"})
        documents = [rss]
        if self.page_fallback_limit == 0:
            return documents
        for item in _xml_items(rss.content)[: self.page_fallback_limit]:
            advisory_url = _safe_url(item.get("link"))
            if advisory_url is None or _FG_IR_RE.search(advisory_url) is None:
                continue
            documents.append(self._get(advisory_url, headers={"Accept": "text/html"}))
        return documents

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        if raw.media_type == "text/html":
            return FortinetAdvisoryPageConnector().normalize(raw)
        records: list[CanonicalRecord] = _catalog_records(
            vendor_id="fortinet",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
        )
        for item in _xml_items(raw.content):
            advisory_url = _safe_url(item.get("link"))
            advisory_match = _FG_IR_RE.search(advisory_url or "")
            if advisory_match is None:
                continue
            advisory_id = advisory_match.group(0).upper()
            description = item.get("description") or ""
            structured_description = BeautifulSoup(description, "html.parser").get_text(" ", strip=True)
            score_match = re.search(
                r"CVSSv?3(?:\.\d)?\s*Score\s*:\s*([0-9]+(?:\.[0-9]+)?)",
                structured_description,
                re.IGNORECASE,
            )
            score = float(score_match.group(1)) if score_match else None
            csaf_url = _safe_url(item.get("https://fortiguard.fortinet.com/rss/ns/csaf:link"))
            urls = [link for link in (advisory_url, csaf_url) if link]
            records.append(
                Advisory(
                    id=advisory_id,
                    vendor_id="fortinet",
                    title=_text(item.get("title")) or advisory_id,
                    published=_parse_datetime(item.get("pubdate")),
                    severity=_severity_from_score(score),
                    cvss=score,
                    cves=_cves(structured_description),
                    urls=_unique(urls),
                    provenance=[
                        _provenance(
                            source=self.id,
                            fetched_at=raw.fetched_at,
                            url=raw.url,
                            license_name=self.license.name,
                            field="advisory",
                        )
                    ],
                )
            )
        return records

    def healthcheck(self) -> HealthStatus:
        if self.page_fallback_limit == 0:
            return HealthStatus(available=True, detail="FortiGuard PSIRT RSS reachable; page fallback disabled")
        try:
            document = self._get(self.url)
        except ConnectorFetchError as exc:
            return HealthStatus(available=False, detail=str(exc))
        return HealthStatus(available=bool(document.content), detail="FortiGuard PSIRT RSS reachable")


def _fortinet_payload(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """Support a recorded facts fixture as well as a raw CVE v5 record."""

    facts = _as_mapping(payload.get("facts"))
    if facts is not None:
        metadata: Mapping[str, Any] = {
            "cveId": facts.get("cve_id"),
            "assignerShortName": facts.get("assigner_short_name"),
        }
        cna: Mapping[str, Any] = {
            "title": facts.get("title"),
            "affected": facts.get("affected"),
            "solutions": [{"value": " ".join(facts.get("fixed_versions", []))}],
            "metrics": [{"cvssV3_1": {"baseScore": facts.get("cvss_v3_1")}}],
            "references": [{"url": facts.get("reference")}],
            "providerMetadata": {"shortName": facts.get("assigner_short_name")},
        }
        return metadata, cna, facts
    cve_metadata: Mapping[str, Any] = _as_mapping(payload.get("cveMetadata")) or {}
    containers = _as_mapping(payload.get("containers")) or {}
    cna = _as_mapping(containers.get("cna")) or {}
    return cve_metadata, cna, {}


def _fortinet_train(value: str) -> str | None:
    candidates = _version_values(value)
    for candidate in candidates:
        if re.fullmatch(r"\d+\.\d+", candidate):
            return candidate
        train = _train(candidate)
        if train is not None:
            return train
    return None


def _fortinet_affected_bounds(
    value: str,
    train: str,
) -> tuple[Literal["affected", "not_affected"] | None, str | None, str | None]:
    normalized = value.casefold()
    if "not affected" in normalized:
        return "not_affected", None, None
    versions = [version for version in _version_values(value) if _train(version) == train]
    if "all versions" in normalized:
        return "affected", None, None
    if not versions:
        return None, None, None
    range_evidence = bool(re.search(r"\b(?:through|to)\b|[-–]", value, re.IGNORECASE))
    if len(versions) > 1 and range_evidence:
        return "affected", versions[0], versions[-1]
    if len(versions) == 1:
        return "affected", versions[0], None
    # A list without explicit range grammar is not enough evidence to infer a
    # contiguous range; leave applicability unknown rather than selecting one.
    return None, None, None


class FortinetCnaConnector(_HttpConnector):
    id: ClassVar[str] = "fortinet_cna"
    vendor_scope: ClassVar[list[str]] = ["fortinet"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "CVE List V5 backbone owns polling"
    schedule: ClassVar[int] = 900

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(allowed_hosts={"raw.githubusercontent.com"}, timeout=timeout, client=client)
        self.license = _license(
            "CVE Program records",
            "https://www.cve.org/ResourcesSupport/TermsOfUse",
            "CVE Program record; keep CVE attribution and source links. Review CNA terms before redistribution.",
            "review",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        del since
        # CveListV5Connector owns CVE List polling. This adapter only maps the
        # already-fetched raw CVE record, avoiding a duplicate full-corpus sync.
        return []

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = _json(raw.content)
        if not isinstance(payload, Mapping):
            return []
        metadata, cna, facts = _fortinet_payload(payload)
        cve_id = _text(metadata.get("cveId"))
        provider = _as_mapping(cna.get("providerMetadata")) or {}
        if not cve_id or (_text(provider.get("shortName")) or _text(metadata.get("assignerShortName"))) != "fortinet":
            return []
        references = _as_list(cna.get("references"))
        urls = [
            link
            for reference in references
            for link in [_safe_url((_as_mapping(reference) or {}).get("url"))]
            if link
        ]
        advisory_id = next(
            (match.group(0).upper() for url in urls if (match := _FG_IR_RE.search(url))),
            cve_id,
        )
        score, _ = _score_from_metrics(cna.get("metrics"))
        if score is None:
            score = _number(facts.get("cvss_v3_1"))
        ranges: list[AffectedRange] = []
        for affected in _as_list(cna.get("affected")):
            affected_mapping = _as_mapping(affected)
            if affected_mapping is None:
                continue
            product_name = _text(affected_mapping.get("product"))
            canonical_product = _canonical_product_id("fortinet", product_name, "fortinet-unknown")
            for version_item in _as_list(affected_mapping.get("versions")):
                version_mapping = _as_mapping(version_item)
                if version_mapping is None or _text(version_mapping.get("status")) != "affected":
                    continue
                lower = _text(version_mapping.get("version"))
                upper = _text(version_mapping.get("lessThan")) or _text(version_mapping.get("lessThanOrEqual"))
                if lower is None:
                    continue
                if upper is None:
                    version_range = VersionRange(exact=lower, train=_train(lower))
                else:
                    version_range = VersionRange(
                        lower=lower,
                        upper=upper,
                        train=_train(lower),
                        include_upper=version_mapping.get("lessThanOrEqual") is not None,
                    )
                ranges.append(
                    AffectedRange(
                        advisory_id=advisory_id,
                        product_id=canonical_product,
                        versions=version_range,
                        status="affected",
                        provenance=[
                            _provenance(
                                source=self.id,
                                fetched_at=raw.fetched_at,
                                url=raw.url,
                                license_name=self.license.name,
                                field="ranges",
                            )
                        ],
                    )
                )
        # The facts-only fixture records its affected rows directly.
        if not ranges:
            for affected in _as_list(facts.get("affected")):
                affected_mapping = _as_mapping(affected)
                if affected_mapping is None or _text(affected_mapping.get("status")) != "affected":
                    continue
                lower = _text(affected_mapping.get("version"))
                if lower is None:
                    continue
                upper = _text(affected_mapping.get("less_than_or_equal"))
                canonical_product = _canonical_product_id(
                    "fortinet", _text(affected_mapping.get("product")), "fortinet-unknown"
                )
                ranges.append(
                    AffectedRange(
                        advisory_id=advisory_id,
                        product_id=canonical_product,
                        versions=(
                            VersionRange(
                                lower=lower,
                                upper=upper,
                                train=_train(lower),
                                include_upper=True,
                            )
                            if upper
                            else VersionRange(exact=lower, train=_train(lower))
                        ),
                        status="affected",
                        provenance=[
                            _provenance(
                                source=self.id,
                                fetched_at=raw.fetched_at,
                                url=raw.url,
                                license_name=self.license.name,
                                field="ranges",
                            )
                        ],
                    )
                )
        targets = _version_values(" ".join(str(item.get("value", "")) for item in _as_list(cna.get("solutions"))))
        targets.extend(_version_values(facts.get("fixed_versions")))
        targets = _sorted_versions(targets)
        remediation = Remediation(targets=targets) if targets else None
        title = _text(cna.get("title")) or cve_id
        advisory = Advisory(
                id=advisory_id,
                vendor_id="fortinet",
                title=title,
                published=_parse_datetime(metadata.get("datePublished")),
                updated=_parse_datetime(metadata.get("dateUpdated")),
                severity=_severity_from_score(score),
                cvss=score,
                cves=[cve_id.upper()],
                urls=_unique(urls),
                ranges=ranges,
                remediation=remediation,
                provenance=[
                    _provenance(
                        source=self.id,
                        fetched_at=raw.fetched_at,
                        url=raw.url,
                        license_name=self.license.name,
                        field="advisory",
                    )
                ],
            )
        product_names = [
            _text((_as_mapping(item) or {}).get("product"))
            for item in _as_list(cna.get("affected"))
        ]
        product_names.extend(
            _text((_as_mapping(item) or {}).get("product"))
            for item in _as_list(facts.get("affected"))
        )
        catalog = _catalog_records(
            vendor_id="fortinet",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
            product_names=[name for name in product_names if name],
        )
        return [*catalog, advisory]

    def healthcheck(self) -> HealthStatus:
        return HealthStatus(
            available=False,
            detail="CVE List V5 backbone must supply raw records; Fortinet CNA adapter does not poll",
        )


class FortinetAdvisoryPageConnector(_HttpConnector):
    id: ClassVar[str] = "fortinet_psirt_page"
    vendor_scope: ClassVar[list[str]] = ["fortinet"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "on-demand; provider-defined"
    schedule: ClassVar[int] = 900
    base_url: ClassVar[str] = "https://fortiguard.fortinet.com/psirt/"

    def __init__(
        self,
        *,
        advisory_ids: Sequence[str] = (),
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(allowed_hosts={"fortiguard.fortinet.com"}, timeout=timeout, client=client)
        self.advisory_ids = tuple(advisory_ids)
        self.license = _license(
            "FortiGuard PSIRT advisory pages",
            "https://www.fortiguard.com/psirt_policy",
            "FortiGuard PSIRT; structured facts and source links only. Page redistribution terms require review.",
            "restricted",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        del since
        documents: list[RawDocument] = []
        for advisory_id in self.advisory_ids:
            match = _FG_IR_RE.fullmatch(advisory_id.strip())
            if match is None:
                raise ConnectorFetchError("Fortinet advisory ID is invalid")
            url = self.base_url + match.group(0).upper()
            documents.append(self._get(url, headers={"Accept": "text/html"}))
        return documents

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        soup = BeautifulSoup(raw.content, "html.parser")
        text_content = soup.get_text(" ", strip=True)
        advisory_match = _FG_IR_RE.search(raw.url) or _FG_IR_RE.search(text_content)
        if advisory_match is None:
            return []
        advisory_id = advisory_match.group(0).upper()
        title = _text(soup.title.get_text(" ", strip=True) if soup.title else None) or advisory_id
        title = re.sub(r"\s+", " ", title)
        score_match = re.search(r"CVSSv?3(?:\.\d)?\s*(?:Base\s*)?Score\s*:\s*([0-9]+(?:\.[0-9]+)?)", text_content, re.IGNORECASE)
        score = float(score_match.group(1)) if score_match else None
        published = None
        published_meta = soup.find("meta", attrs={"property": "article:published_time"})
        if published_meta is not None:
            published = _parse_datetime(published_meta.get("content"))
        ranges: list[AffectedRange] = []
        scoped_fixes: list[tuple[str, str, list[str]]] = []
        # Only consume the table whose header explicitly identifies the
        # product/train, affected-version, and solution columns. Other tables
        # on FortiGuard pages contain unrelated metadata and prose.
        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            if not rows:
                continue
            header = [re.sub(r"\s+", " ", cell.get_text(" ", strip=True)).casefold() for cell in rows[0].find_all(["th", "td"])]
            if not {"version", "affected", "solution"}.issubset(header):
                continue
            columns = {name: header.index(name) for name in ("version", "affected", "solution")}
            for row in rows[1:]:
                cells = [re.sub(r"\s+", " ", cell.get_text(" ", strip=True)) for cell in row.find_all(["th", "td"])]
                if len(cells) <= max(columns.values()):
                    continue
                product_train_text = cells[columns["version"]]
                affected_text = cells[columns["affected"]]
                solution_text = cells[columns["solution"]]
                product_id = _canonical_product_id("fortinet", product_train_text, "fortinet-unknown")
                if product_id == "fortinet-unknown":
                    continue
                train = _fortinet_train(product_train_text)
                if train is None:
                    continue
                status, lower, upper = _fortinet_affected_bounds(affected_text, train)
                if status is None:
                    continue
                row_provenance = _provenance(
                    source=self.id,
                    fetched_at=raw.fetched_at,
                    url=raw.url,
                    license_name=self.license.name,
                    field=f"ranges.{product_id}.{train}",
                )
                version_range = (
                    VersionRange(train=train)
                    if lower is None
                    else VersionRange(
                        exact=lower,
                        train=train,
                    )
                    if upper is None
                    else VersionRange(
                        lower=lower,
                        upper=upper,
                        train=train,
                        include_upper=True,
                    )
                )
                targets = [
                    value
                    for value in _version_values(solution_text)
                    if _train(value) == train
                ]
                ranges.append(
                    AffectedRange(
                        advisory_id=advisory_id,
                        product_id=product_id,
                        versions=version_range,
                        status=status,
                        fixed_versions=_sorted_versions(targets),
                        provenance=[row_provenance],
                    )
                )
                if status == "affected" and targets:
                    scoped_fixes.append((product_id, train, _sorted_versions(targets)))
                    for target in _sorted_versions(targets):
                        ranges.append(
                            AffectedRange(
                                advisory_id=advisory_id,
                                product_id=product_id,
                                versions=VersionRange(lower=target, train=train),
                                status="fixed",
                                fixed_versions=[target],
                                provenance=[row_provenance.model_copy(update={"field": f"fixed.{product_id}.{train}"})],
                            )
                        )
        remediation_targets = scoped_fixes[0][2] if len(scoped_fixes) == 1 else []
        advisory = Advisory(
                id=advisory_id,
                vendor_id="fortinet",
                title=title,
                published=published,
                severity=_severity_from_score(score),
                cvss=score,
                cves=_cves(text_content),
                urls=[raw.url],
                ranges=ranges,
                remediation=Remediation(targets=remediation_targets) if remediation_targets else None,
                provenance=[
                    _provenance(
                        source=self.id,
                        fetched_at=raw.fetched_at,
                        url=raw.url,
                        license_name=self.license.name,
                        field="advisory",
                    )
                ],
            )
        product_names = [item.product_id for item in ranges]
        catalog = _catalog_records(
            vendor_id="fortinet",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
            product_names=product_names,
        )
        return [*catalog, advisory]

    def healthcheck(self) -> HealthStatus:
        if not self.advisory_ids:
            return HealthStatus(available=False, detail="no Fortinet advisory IDs configured for page fallback")
        return HealthStatus(available=True, detail="FortiGuard page fallback is configured")
