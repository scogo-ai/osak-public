"""Arista advisory-index and CSAF connector."""

from __future__ import annotations

import re
import shutil
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from osak.connectors.base import HealthStatus, RawDocument
from osak.connectors.oem_common import (
    ConnectorFetchError,
    CsafValidator,
    _as_mapping,
    _catalog_records,
    _CsafValidationMixin,
    _cves,
    _default_csaf_validator,
    _HttpConnector,
    _json,
    _license,
    _number,
    _parse_datetime,
    _provenance,
    _safe_url,
    _severity_from_score,
    _text,
    _train,
    _unique,
    normalize_csaf,
)
from osak.core.models import Advisory, AffectedRange, CanonicalRecord, Condition, VersionRange


def _meta_content(soup: BeautifulSoup, property_name: str) -> str | None:
    meta = soup.find("meta", attrs={"property": property_name})
    value = meta.get("content") if meta is not None else None
    return value if isinstance(value, str) else None


def _section_text(soup: BeautifulSoup, heading: str) -> str:
    target = None
    for element in soup.find_all(["h2", "h3", "h4", "h5"]):
        if heading.casefold() in element.get_text(" ", strip=True).casefold():
            target = element
            break
    if target is None:
        return ""
    target_level = int(target.name[1])
    parts: list[str] = []
    for sibling in target.find_all_next():
        if (
            sibling.name in {"h2", "h3", "h4", "h5"}
            and sibling is not target
            and int(sibling.name[1]) <= target_level
        ):
            break
        if sibling.name in {"p", "li"}:
            text = sibling.get_text(" ", strip=True)
            if text:
                parts.append(text)
    return " ".join(dict.fromkeys(parts))


def _page_conditions(soup: BeautifulSoup) -> list[Condition]:
    section = None
    for element in soup.find_all(["h2", "h3"]):
        if "required configuration" in element.get_text(" ", strip=True).casefold():
            section = element
            break
    if section is None:
        return []
    section_text_parts: list[str] = []
    for sibling in section.find_all_next():
        if sibling.name in {"h2", "h3"} and sibling is not section:
            break
        if sibling.name in {"p", "li"}:
            text = re.sub(r"^[–—-]\s*", "", sibling.get_text(" ", strip=True))
            if text:
                section_text_parts.append(text)
    section_text = " ".join(dict.fromkeys(section_text_parts)).casefold()
    base_supported = "at least two" in section_text and "ip helper-address" in section_text
    no_source_interface = "does not use a source-interface" in section_text
    no_vrf = "does not use a vrf" in section_text
    scenario_one = "scenario one" in section_text and "source-interface" in section_text
    scenario_two = "scenario two" in section_text and "inside of a vrf" in section_text
    if not (base_supported and no_source_interface and no_vrf and scenario_one and scenario_two):
        return []
    return [
        Condition(
            feature="dhcp_relay_multiple_helpers_on_same_interface",
            method="parsed",
            reviewed=True,
        ),
        Condition(
            feature="dhcp_relay_mixed_source_interface_or_vrf",
            method="parsed",
            reviewed=True,
        ),
    ]


class AristaCsafConnector(_CsafValidationMixin, _HttpConnector):
    id: ClassVar[str] = "arista_csaf"
    vendor_scope: ClassVar[list[str]] = ["arista"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "30 minute poll; provider-defined"
    schedule: ClassVar[int] = 1800
    index_url: ClassVar[str] = "https://www.arista.com/en/support/advisories-notices/securityadvisory"

    def __init__(
        self,
        *,
        max_advisories: int = 500,
        validator: CsafValidator | None = None,
        validator_binary: str = "csaf_validator",
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(allowed_hosts={"www.arista.com"}, timeout=timeout, client=client)
        self.max_advisories = max_advisories
        self._setup_validator(validator, validator_binary)
        self.license = _license(
            "Arista Security Advisories terms pending",
            "https://www.arista.com/en/terms-of-use",
            "Arista PSIRT; structured facts and source links only. Review Arista terms before redistribution.",
            "review",
        )

    def extract_csaf_urls(self, raw: RawDocument) -> list[str]:
        soup = BeautifulSoup(raw.content, "html.parser")
        urls: list[str] = []
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href"))
            if not re.search(r"/assets/data/SecurityAdvisories/CSAF/[^/]+\.json$", href, re.IGNORECASE):
                continue
            absolute = urljoin("https://www.arista.com", href)
            if _safe_url(absolute):
                urls.append(absolute)
        return _unique(urls)[: self.max_advisories]

    def extract_advisory_urls(self, raw: RawDocument) -> list[str]:
        """Extract advisory-page links from the public index before CSAF links."""

        soup = BeautifulSoup(raw.content, "html.parser")
        urls: list[str] = []
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href"))
            if not re.search(
                r"/en/support/advisories-notices/security-advisory/[^/?#]+$", href, re.IGNORECASE
            ):
                continue
            absolute = urljoin("https://www.arista.com", href)
            if _safe_url(absolute):
                urls.append(absolute)
        return _unique(urls)[: self.max_advisories]

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        index = self._get(self.index_url, headers={"Accept": "text/html"})
        documents: list[RawDocument] = []
        with tempfile.TemporaryDirectory(prefix="osak-arista-csaf-") as directory:
            output_dir = Path(directory)
            advisory_pages = self.extract_advisory_urls(index)
            # Some index snapshots expose direct CSAF links; retain that path
            # for those snapshots while preferring page -> CSAF discovery.
            page_csaf_urls: list[str] = []
            page_documents: list[RawDocument] = []
            for page_url in advisory_pages:
                page = self._get(page_url, headers={"Accept": "text/html"})
                page_documents.append(page)
                page_csaf_urls.extend(self.extract_csaf_urls(page))
            csaf_urls = _unique(page_csaf_urls or self.extract_csaf_urls(index))
            for url in csaf_urls[: self.max_advisories]:
                document = self._get(url, headers={"Accept": "application/json"})
                if since is not None:
                    payload = _json(document.content)
                    metadata = _as_mapping(payload.get("document")) if isinstance(payload, Mapping) else None
                    tracking = _as_mapping((metadata or {}).get("tracking")) or {}
                    updated = _parse_datetime(tracking.get("current_release_date"))
                    if updated is not None and updated < since:
                        continue
                path_name = Path(urlparse(url).path).name or "arista-advisory.json"
                validation = self.validate_document(document, path=output_dir / path_name)
                if validation.ok:
                    documents.append(document)
        return [*page_documents, *documents]

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        if raw.media_type.startswith("text/html"):
            return self.normalize_page(raw, source_id="arista_psirt_page")
        payload = _json(raw.content)
        if not isinstance(payload, Mapping):
            return []
        return normalize_csaf(
            payload,
            source=self.id,
            source_url=raw.url,
            fetched_at=raw.fetched_at,
            vendor_id="arista",
            vendor_name="Arista",
            product_id="arista-eos",
            product_family="EOS",
            scheme="arista_eos",
            license_name=self.license.name,
        )

    def normalize_page(
        self,
        raw: RawDocument,
        *,
        source_id: str | None = None,
    ) -> Iterable[CanonicalRecord]:
        """Normalize only explicit introduced-release and scope facts from a page.

        The HTML page's affected-version bullets are intentionally not expanded
        into a later-release range; the CSAF product tree remains the source of
        those applicability labels. This page adapter records the exact release
        where Arista says the issue was introduced, plus the required condition,
        when the page explicitly identifies EOS and platform-independent scope.
        """

        soup = BeautifulSoup(raw.content, "html.parser")
        page_text = soup.get_text(" ", strip=True)
        advisory_match = re.search(r"security-advisory-(\d+)", raw.url, re.IGNORECASE)
        if advisory_match is None:
            advisory_match = re.search(r"Security Advisory\s+0*(\d+)", page_text, re.IGNORECASE)
        if advisory_match is None:
            return []
        advisory_id = f"Arista SA {int(advisory_match.group(1)):04d}"
        affected_software = _section_text(soup, "Affected Software")
        platform_scope = _section_text(soup, "Affected Platforms")
        if not re.search(r"introduced\s+in\s+EOS\s+version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?[FM]?)", affected_software, re.IGNORECASE):
            return []
        if not re.search(r"platform-independent", platform_scope, re.IGNORECASE) or not re.search(
            r"systems\s+running\s+EOS", platform_scope, re.IGNORECASE
        ):
            return []
        introduced_match = re.search(
            r"introduced\s+in\s+EOS\s+version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?[FM]?)",
            affected_software,
            re.IGNORECASE,
        )
        if introduced_match is None:
            return []
        introduced = introduced_match.group(1)
        train = _train(introduced)
        if train is None:
            return []
        conditions = _page_conditions(soup)
        if not conditions:
            return []
        score_match = re.search(
            r"CVSSv?3(?:\.\d)?\s*(?:Base\s*)?Score\s*:\s*([0-9]+(?:\.[0-9]+)?)",
            page_text,
            re.IGNORECASE,
        )
        score = _number(score_match.group(1)) if score_match else None
        fetched_at = raw.fetched_at
        source = source_id or self.id
        license_name = self.license.name
        provenance = _provenance(
            source=source,
            fetched_at=fetched_at,
            url=raw.url,
            license_name=license_name,
            field="page.introduced_release",
        )
        range_record = AffectedRange(
            advisory_id=advisory_id,
            product_id="arista-eos",
            versions=VersionRange(exact=introduced, train=train),
            status="affected",
            conditions=conditions,
            provenance=[provenance],
        )
        condition_provenance = _provenance(
            source=source,
            fetched_at=fetched_at,
            url=raw.url,
            license_name=license_name,
            field="page.condition",
        )
        advisory = Advisory(
            id=advisory_id,
            vendor_id="arista",
            title=_text(soup.title.get_text(" ", strip=True) if soup.title else None) or advisory_id,
            published=_parse_datetime(_meta_content(soup, "article:published_time")),
            updated=_parse_datetime(_meta_content(soup, "article:modified_time")),
            severity=_severity_from_score(score),
            cvss=score,
            cves=_cves(page_text),
            urls=[raw.url],
            ranges=[range_record],
            provenance=[
                _provenance(
                    source=source,
                    fetched_at=fetched_at,
                    url=raw.url,
                    license_name=license_name,
                    field="page.advisory",
                ),
                condition_provenance,
            ],
        )
        catalog = _catalog_records(
            vendor_id="arista",
            source=source,
            fetched_at=fetched_at,
            url=raw.url,
            license_name=license_name,
            product_names=["EOS"],
        )
        return [*catalog, advisory]

    def healthcheck(self) -> HealthStatus:
        if shutil.which(self.validator_binary) is None and self.validator is _default_csaf_validator:
            return HealthStatus(available=False, detail="gocsaf csaf_validator is not installed")
        if self.quarantined:
            return HealthStatus(
                available=False,
                detail=f"{len(self.quarantined)} Arista CSAF document(s) quarantined: {self.quarantined[-1].reason}",
            )
        try:
            index = self._get(self.index_url, headers={"Accept": "text/html"})
        except ConnectorFetchError as exc:
            return HealthStatus(available=False, detail=f"Arista advisory index unavailable: {exc}")
        if not self.extract_advisory_urls(index) and not self.extract_csaf_urls(index):
            return HealthStatus(available=False, detail="Arista advisory index returned no usable advisory links")
        return HealthStatus(available=True, detail="Arista advisory index and CSAF validator configured")
