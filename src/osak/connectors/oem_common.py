"""Read-only OEM advisory and lifecycle connectors.

The connectors in this module deliberately normalize only structured facts.  OEM
pages and CSAF documents can contain long descriptions, mitigations, examples,
or exploit instructions; those fields are not copied into the canonical model.
Source links and source terms stay attached to every normalized record.
"""

from __future__ import annotations

import hashlib
import json
import re

# subprocess is restricted to software-owned gocsaf binaries and shell=False.
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlparse

import defusedxml.ElementTree as SafeET  # type: ignore[import-untyped]
import httpx

from osak.connectors.base import RawDocument, SourceLicense
from osak.core.catalog import resolve_product, resolve_vendor
from osak.core.models import (
    Advisory,
    AffectedRange,
    CanonicalRecord,
    ClosedScopeEvidence,
    Product,
    Provenance,
    Remediation,
    VersionRange,
)
from osak.versions import get_scheme

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_FG_IR_RE = re.compile(r"\bFG-IR-\d{2}-\d{1,5}\b", re.IGNORECASE)
_ARISTA_SA_RE = re.compile(
    r"(?:Arista(?:\s+Networks)?\s+)?Security\s+Advisory\s+0*(\d{1,5})", re.IGNORECASE
)
_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])\d+\.\d+"
    r"(?:\([0-9]+\))?"
    r"(?:[A-Za-z]+[0-9]*(?:\([0-9]+\))?)?"
    r"(?:\.[0-9A-Za-z]+)*"
    r"(?:-[A-Za-z0-9.]+)?"
)

HttpClientFactory = Callable[[], httpx.Client]


class ConnectorFetchError(RuntimeError):
    """Raised when a source cannot be fetched or safely decoded."""


class GocSafRunner(Protocol):
    def __call__(self, command: list[str], output_dir: Path) -> None: ...


def _now() -> datetime:
    return datetime.now(UTC)


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _safe_url(value: Any) -> str | None:
    text_value = _text(value)
    if not text_value:
        return None
    parsed = urlparse(text_value)
    if parsed.scheme != "https" or not parsed.netloc:
        return None
    return text_value


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            if candidate.endswith("Z"):
                candidate = f"{candidate[:-1]}+00:00"
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(candidate)
            except (TypeError, ValueError, OverflowError):
                return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    parsed = _parse_datetime(value)
    if parsed is not None:
        return parsed.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip()[:10])
        except ValueError:
            return None
    return None


def _version_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return _unique(_VERSION_RE.findall(value))
    if isinstance(value, (list, tuple, set)):
        return _unique(item for part in value for item in _version_values(part))
    return []


def _version_sort_key(value: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for token in re.split(r"[.\-_]", value.lower()):
        match = re.fullmatch(r"(\d+)([a-z]*)", token)
        if match:
            parts.append((0, int(match.group(1))))
            if match.group(2):
                parts.append((1, match.group(2)))
        else:
            parts.append((1, token))
    return tuple(parts)


def _sorted_versions(values: Iterable[str]) -> list[str]:
    return sorted(_unique(values), key=_version_sort_key)


def _train(value: str | None) -> str | None:
    if not value:
        return None
    numbers = re.match(r"^(\d+\.\d+)", value)
    return numbers.group(1) if numbers else None


def _cves(value: Any) -> list[str]:
    if isinstance(value, list):
        candidates = (item for item in value if isinstance(item, str))
        return _unique(item.upper() for item in candidates if _CVE_RE.fullmatch(item.strip()))
    return _unique(match.upper() for match in _CVE_RE.findall(_text(value) or ""))


def _severity_from_value(value: Any) -> Literal["critical", "high", "medium", "low", "unknown"]:
    text_value = (_text(value) or "").lower()
    for severity in ("critical", "high", "medium", "low"):
        if severity in text_value:
            return severity
    return "unknown"


def _severity_from_score(score: float | None) -> Literal["critical", "high", "medium", "low", "unknown"]:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.search(r"\b(?:10(?:\.0)?|[0-9](?:\.\d)?)\b", value)
        if match:
            try:
                return float(match.group(0))
            except ValueError:
                return None
    return None


def _score_from_metrics(metrics: Any) -> tuple[float | None, str | None]:
    for metric in _as_list(metrics):
        mapping = _as_mapping(metric)
        if mapping is None:
            continue
        for key in ("cvss_v4", "cvss_v3", "cvssV4_0", "cvssV3_1", "cvssV3"):
            candidate = _as_mapping(mapping.get(key))
            if candidate is None:
                continue
            score = _number(candidate.get("baseScore"))
            version = _text(candidate.get("version")) or ("4.0" if "4" in key else "3.1")
            if score is not None:
                return score, version
    return None, None


def _provenance(
    *, source: str, fetched_at: datetime, url: str, license_name: str, field: str = "*"
) -> Provenance:
    return Provenance(
        source=source,
        fetched_at=fetched_at,
        url=url,
        license=license_name,
        field=field,
    )


def _canonical_product_id(vendor_id: str, value: str | None, default: str) -> str:
    text_value = (value or "").lower()
    if vendor_id == "fortinet":
        if "fortios" in text_value:
            return "fortinet-fortios"
        if "fortisase" in text_value:
            return "fortinet-fortisase"
        if "fortiproxy" in text_value:
            return "fortinet-fortiproxy"
    if vendor_id == "arista" or "eos" in text_value:
        return "arista-eos" if vendor_id == "arista" or "eos" in text_value else default
    if "ios xe" in text_value or "ios-xe" in text_value or "iosxe" in text_value:
        return "cisco-iosxe"
    if "nx-os" in text_value or "nxos" in text_value:
        return "cisco-nxos"
    if "asa" in text_value:
        return "cisco-asa"
    if "ios" in text_value:
        return "cisco-ios"
    if default.startswith(f"{vendor_id}-"):
        return default
    return f"{vendor_id}-{default}" if default else default


def _license(
    name: str,
    url: str,
    attribution: str,
    redistribution: Literal["facts", "restricted", "review"],
) -> SourceLicense:
    return SourceLicense(
        name=name,
        url=url,
        attribution=attribution,
        redistribution=redistribution,
    )


class PublisherHTTPError(ConnectorFetchError):
    def __init__(self, status: int, *, no_data_found: bool = False) -> None:
        self.status = status
        self.no_data_found = no_data_found
        super().__init__(f"source returned HTTP {status}")


def _safe_response_document(
    response: httpx.Response,
    *,
    url: str,
    fetched_at: datetime | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    allowed_hosts: set[str] | frozenset[str],
) -> RawDocument:
    if response.status_code >= 400:
        no_data = False
        if response.status_code == 404 and len(response.content) <= 4096:
            try:
                error = response.json()
            except ValueError:
                error = None
            no_data = isinstance(error, dict) and error.get("errorCode") == "NO_DATA_FOUND"
        raise PublisherHTTPError(response.status_code, no_data_found=no_data)
    final_host = (urlparse(str(response.url)).hostname or "").lower()
    if final_host not in allowed_hosts:
        raise ConnectorFetchError("source redirected outside the configured host allow-list")
    content = response.content
    if len(content) > max_bytes:
        raise ConnectorFetchError("source response exceeds connector size limit")
    media_type = response.headers.get("content-type", "application/octet-stream").split(";", 1)[0]
    return RawDocument(
        url=url,
        fetched_at=fetched_at or _now(),
        content=content,
        media_type=media_type,
    )


class _HttpConnector:
    """Small fixed-host HTTP helper shared by public-source connectors."""

    allowed_hosts: frozenset[str]
    timeout: float
    client: httpx.Client | None

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str],
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.timeout = timeout
        self.client = client

    def _get(self, url: str, *, headers: Mapping[str, str] | None = None) -> RawDocument:
        parsed = urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in self.allowed_hosts:
            raise ConnectorFetchError("connector URL is outside the configured host allow-list")
        own_client = self.client is None
        client = self.client or httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "OSAK/0.1.0 (+https://osak.lab.scogo.ai)"},
        )
        try:
            response = client.get(url, headers=dict(headers or {}))
            return _safe_response_document(
                response,
                url=url,
                allowed_hosts=self.allowed_hosts,
            )
        except httpx.HTTPError as exc:
            raise ConnectorFetchError("source request failed") from exc
        finally:
            if own_client:
                client.close()


def _json(content: bytes) -> Mapping[str, Any] | list[Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorFetchError("source response was not valid JSON") from exc
    if not isinstance(value, (Mapping, list)):
        raise ConnectorFetchError("source JSON root must be an object or array")
    return value


def _xml_items(content: bytes) -> list[Mapping[str, Any]]:
    try:
        root = SafeET.fromstring(content)
    except Exception as exc:
        raise ConnectorFetchError("source response was not valid XML") from exc
    items: list[Mapping[str, Any]] = []
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1].lower() != "item":
            continue
        values: dict[str, Any] = {}
        for child in list(item):
            key = child.tag.rsplit("}", 1)[-1].lower()
            value = (child.text or "").strip()
            if key == "link" and child.tag.startswith("{"):
                namespace, _, local = child.tag[1:].partition("}")
                values[f"{namespace}:{local}".lower()] = value
            elif value:
                values[key] = value
        items.append(values)
    return items


def _base_product(
    *,
    vendor_id: str,
    product_id: str,
    family: str,
    scheme: str,
    aliases: Iterable[str],
    csaf_ids: Iterable[str],
    provenance: Provenance,
) -> Product:
    catalog_product = resolve_product(vendor_id, family)
    if catalog_product is None:
        catalog_product = resolve_product(vendor_id, product_id)
    if catalog_product is None:
        return Product(
            id=product_id,
            vendor_id=vendor_id,
            family=family,
            os=scheme,
            scheme=scheme,
            aliases=_unique(aliases),
            csaf_ids=_unique(csaf_ids),
            vendor_names=_unique(aliases),
            cpe_prefixes=[],
            provenance=[provenance],
        )
    return catalog_product.model_copy(
        update={
            "aliases": _unique([*catalog_product.aliases, *aliases]),
            "csaf_ids": _unique([*catalog_product.csaf_ids, *csaf_ids]),
            "vendor_names": _unique([*catalog_product.vendor_names, *aliases]),
            "provenance": [provenance],
        }
    )


def _catalog_records(
    *,
    vendor_id: str,
    source: str,
    fetched_at: datetime,
    url: str,
    license_name: str,
    product_names: Iterable[str] = (),
) -> list[CanonicalRecord]:
    """Emit catalog identities with connector provenance, never inferred aliases."""

    provenance = _provenance(
        source=source,
        fetched_at=fetched_at,
        url=url,
        license_name=license_name,
        field="catalog",
    )
    vendor = resolve_vendor(vendor_id)
    records: list[CanonicalRecord] = []
    if vendor is not None:
        records.append(vendor.model_copy(update={"provenance": [provenance]}))
    seen: set[str] = set()
    for name in product_names:
        product = resolve_product(vendor_id, name)
        if product is None or product.id in seen:
            continue
        seen.add(product.id)
        records.append(product.model_copy(update={"provenance": [provenance]}))
    return records


def _csaf_product_map(
    tree: Any, *, default_family: str
) -> dict[str, tuple[str, str | None, str, str | None]]:
    """Return product_id -> (display_name, version, family, hardware) from a CSAF tree."""

    products: dict[str, tuple[str, str | None, str, str | None]] = {}

    def walk(nodes: Any, family: str = "") -> None:
        for node in _as_list(nodes):
            if not isinstance(node, Mapping):
                continue
            name = _text(node.get("name")) or ""
            category = node.get("category")
            product_family = name if category in {"product_family", "product_name"} else family
            product = _as_mapping(node.get("product"))
            if product:
                pid = _text(product.get("product_id"))
                display = _text(product.get("name")) or name
                if pid:
                    version = _version_from_name(display)
                    if category in {"product_version", "service_pack", "patch_level"}:
                        version = _version_from_name(name) or version
                    products[pid] = (display, version, product_family, None)
            walk(node.get("branches"), product_family)

    if not isinstance(tree, Mapping):
        return products
    walk(tree.get("branches"))
    for relation in _as_list(tree.get("relationships")):
        if not isinstance(relation, Mapping) or relation.get("category") != "installed_on":
            # A software/hotfix combination is not a fixed base-software release.
            continue
        reference = products.get(str(relation.get("product_reference")))
        machine = products.get(str(relation.get("relates_to_product_reference")))
        composite = _as_mapping(relation.get("full_product_name")) or {}
        pid = _text(composite.get("product_id"))
        display = _text(composite.get("name"))
        if not pid or not display:
            continue
        software, separator, hardware = display.partition(" when installed on ")
        if reference and machine:
            products[pid] = (display, reference[1], reference[2], machine[0])
        elif separator:
            products[pid] = (display, _version_from_name(software), software, hardware)
    return products


def _version_from_name(value: str | None) -> str | None:
    if not value:
        return None
    # Keep the complete publisher release token, including the letter in an
    # NX-OS rebuild such as 10.2(1q). Truncation would create a different version.
    release = value.strip().rsplit(" ", 1)[-1]
    if re.fullmatch(r"[0-9]+\.[0-9]+[a-zA-Z0-9.()_-]*", release):
        return release
    return None


def _csaf_advisory_id(vendor_id: str, value: str | None) -> str:
    candidate = value or f"{vendor_id}-advisory-unknown"
    if vendor_id == "arista":
        match = _ARISTA_SA_RE.search(candidate)
        if match:
            return f"Arista SA {int(match.group(1)):04d}"
    return candidate


def _csaf_score(vulnerabilities: Sequence[Any]) -> tuple[float | None, str | None]:
    for vulnerability in vulnerabilities:
        mapping = _as_mapping(vulnerability)
        if mapping is None:
            continue
        score, version = _score_from_metrics(mapping.get("scores"))
        if score is not None:
            return score, version
    return None, None


def _csaf_note(document: Mapping[str, Any], title: str) -> str | None:
    document_meta = _as_mapping(document.get("document")) or {}
    matches: list[str] = []
    for note in _as_list(document_meta.get("notes")):
        mapping = _as_mapping(note)
        if mapping is not None and (_text(mapping.get("title")) or "").casefold() == title.casefold():
            text = _text(mapping.get("text"))
            if text is not None:
                matches.append(text)
    return matches[0] if len(matches) == 1 else None


def _parse_closed_platform_enumeration(text: str) -> set[str]:
    """Recognize a complete hardware clause at the start of the publisher note."""
    paragraph = " ".join(re.split(r"\r?\n\s*\r?\n", text, maxsplit=1)[0].split())
    opening = r"(?:At the time of publication, )?This vulnerability affect(?:s|ed) "
    switches = re.match(opening + r"(.+?) in standalone NX-OS mode\b", paragraph, re.IGNORECASE)
    if switches:
        listed = re.split(r", (?:and |or )?| (?:and|or) ", switches[1], flags=re.IGNORECASE)
        if all(re.fullmatch(r"Cisco Nexus [0-9]+ Series Switches", name, re.IGNORECASE) for name in listed):
            return {name.casefold() for name in listed}
        return set()
    firewall = re.match(
        opening + r"Cisco [^.]+? if (?:they are|it is) running on a Cisco Secure Firewall "
        r"([0-9]+(?: (?:or|and) [0-9]+)*) Series device\b",
        paragraph, re.IGNORECASE,
    )
    if firewall:
        return {
            f"cisco secure firewall {family} series"
            for family in re.split(r" (?:or|and) ", firewall[1], flags=re.IGNORECASE)
        }
    return set()


def _closed_cisco_scope(
    document: Mapping[str, Any],
    *,
    product_map: Mapping[str, tuple[str, str | None, str, str | None]],
    identity_by_pid: Mapping[str, tuple[str, Product | None]],
    vulnerability: Mapping[str, Any],
    vendor_id: str,
    source: str,
    fetched_at: datetime,
    source_url: str,
    license_name: str,
) -> list[ClosedScopeEvidence]:
    """Extract a closed Cisco platform list only from explicit source facts."""

    if vendor_id != "cisco":
        return []
    vulnerable_text = _csaf_note(document, "Vulnerable Products")
    confirmed_text = _csaf_note(document, "Products Confirmed Not Vulnerable")
    only_listed = re.compile(
        r'^\s*only products listed in the vulnerable products(?:\s*\["#vp"\])? '
        r'section(?: of this advisory)? are known to be affected'
        r'(?: by (?:this vulnerability|these vulnerabilities))?\.',
        re.IGNORECASE,
    )
    if not vulnerable_text or not confirmed_text or only_listed.search(confirmed_text) is None:
        return []
    prose_platforms = _parse_closed_platform_enumeration(vulnerable_text)
    if not prose_platforms:
        return []
    product_status = _as_mapping(vulnerability.get("product_status")) or {}
    known_affected = [
        _text(value) for value in _as_list(product_status.get("known_affected"))
    ]
    if not known_affected or any(value is None for value in known_affected):
        return []
    resolved = [product_map.get(value) for value in known_affected if value is not None]
    if any(item is None or item[3] is None for item in resolved):
        return []
    grouped: dict[str, set[str]] = {}
    for value, item in zip(known_affected, resolved, strict=True):
        canonical_product = identity_by_pid.get(value or "", (None, None))[0]
        if canonical_product is None or canonical_product == "cisco-csaf-unknown" or item is None:
            return []
        hardware = item[3]
        if hardware is None:
            return []
        grouped.setdefault(canonical_product, set()).add(hardware)
    if product_status.get("under_investigation") or not grouped:
        return []
    # Each software product must independently cover every named hardware
    # family. A second software product cannot supply its missing relationship.
    if any({model.casefold() for model in models} != prose_platforms for models in grouped.values()):
        return []
    provenance = _provenance(
        source=source,
        fetched_at=fetched_at,
        url=source_url,
        license_name=license_name,
        field="closed_scope",
    )
    return [
        ClosedScopeEvidence(
            vendor_id=vendor_id,
            product_id=product_id,
            hardware_models=sorted(hardware_models),
            complete=True,
            explicit=True,
            provenance=[provenance],
        )
        for product_id, hardware_models in sorted(grouped.items())
    ]


def _csaf_catalog_product(
    vendor_id: str,
    product_family: str,
    display_name: str,
    family: str,
) -> Product | None:
    """Resolve a CSAF product identity without falling back across Cisco OSes."""

    if vendor_id == "cisco":
        labels = (
            ("cisco-asa", ("adaptive security appliance", "asa software")),
            (
                "cisco-ftd",
                (
                    "firepower threat defense",
                    "ftd software",
                    "secure firewall threat defense",
                ),
            ),
            ("cisco-fmc", ("firepower management center", "fmc software")),
            ("cisco-fxos", ("firepower extensible operating system", "fxos software")),
            ("cisco-nxos", ("nx-os", "nxos")),
            ("cisco-iosxe", ("ios xe", "ios-xe")),
        )
        # Prefer the product identity from the branch ancestry. Composite
        # display names can also contain an unrelated hardware product name.
        for text in (family, display_name.partition(" when installed on ")[0]):
            exact = resolve_product(vendor_id, text)
            if exact:
                return exact
            for pid, hints in labels:
                if any(hint in text.casefold() for hint in hints):
                    return resolve_product(vendor_id, pid)
        return None
    return resolve_product(vendor_id, family) or resolve_product(vendor_id, display_name) or (
        resolve_product(vendor_id, product_family) if "eos" in display_name.casefold() else None
    )


def normalize_csaf(
    document: Mapping[str, Any],
    *,
    source: str,
    source_url: str,
    fetched_at: datetime,
    vendor_id: str,
    vendor_name: str,
    product_id: str,
    product_family: str,
    scheme: str,
    license_name: str,
) -> list[CanonicalRecord]:
    """Normalize a CSAF security advisory into a product plus structured facts."""

    document_meta = _as_mapping(document.get("document")) or {}
    tracking = _as_mapping(document_meta.get("tracking")) or {}
    tracking_id = _text(tracking.get("id"))
    advisory_id = _csaf_advisory_id(vendor_id, tracking_id)
    title = _text(document_meta.get("title")) or advisory_id
    published = _parse_datetime(tracking.get("initial_release_date"))
    updated = _parse_datetime(tracking.get("current_release_date"))
    status = _text(tracking.get("status"))
    tree = document.get("product_tree")
    product_map = _csaf_product_map(tree, default_family=product_family)
    provenance = _provenance(
        source=source,
        fetched_at=fetched_at,
        url=source_url,
        license_name=license_name,
        field="product",
    )
    identity_by_pid: dict[str, tuple[str, Product | None]] = {}
    product_groups: dict[str, dict[str, Any]] = {}
    for csaf_pid, (display_name, _version, family, _hardware) in product_map.items():
        catalog_product = _csaf_catalog_product(vendor_id, product_family, display_name, family)
        if catalog_product is not None:
            canonical_id = catalog_product.id
        elif not product_map:
            canonical_id = product_id
        else:
            canonical_id = f"{vendor_id}-csaf-unknown"
        identity_by_pid[csaf_pid] = (canonical_id, catalog_product)
        group = product_groups.setdefault(
            canonical_id,
            {"catalog": catalog_product, "family": family, "aliases": [], "csaf_ids": []},
        )
        group["aliases"].append(display_name)
        group["csaf_ids"].append(csaf_pid)

    if not product_map:
        catalog_product = resolve_product(vendor_id, product_family) or resolve_product(vendor_id, product_id)
        canonical_id = catalog_product.id if catalog_product is not None else product_id
        identity_by_pid[""] = (canonical_id, catalog_product)
        product_groups[canonical_id] = {
            "catalog": catalog_product,
            "family": product_family,
            "aliases": [],
            "csaf_ids": [],
        }

    product_records: list[Product] = []
    for canonical_id, group in product_groups.items():
        catalog_product = group["catalog"]
        aliases = _unique(group["aliases"])
        csaf_ids = _unique(group["csaf_ids"])
        if catalog_product is not None:
            product_records.append(
                catalog_product.model_copy(
                    update={
                        "aliases": _unique([*catalog_product.aliases, *aliases]),
                        "csaf_ids": _unique([*catalog_product.csaf_ids, *csaf_ids]),
                        "vendor_names": _unique([*catalog_product.vendor_names, *aliases]),
                        "provenance": [provenance],
                    }
                )
            )
        else:
            product_records.append(
                Product(
                    id=canonical_id,
                    vendor_id=vendor_id,
                    family=group["family"],
                    os=scheme if canonical_id != f"{vendor_id}-csaf-unknown" else "unknown",
                    scheme=scheme if canonical_id != f"{vendor_id}-csaf-unknown" else "unknown",
                    aliases=aliases,
                    csaf_ids=csaf_ids,
                    vendor_names=aliases,
                    provenance=[provenance],
                )
            )

    references = _as_list(document_meta.get("references"))
    urls = [source_url]
    for reference in references:
        mapping = _as_mapping(reference)
        if mapping is not None:
            link = _safe_url(mapping.get("url"))
            if link:
                urls.append(link)

    vulnerabilities = _as_list(document.get("vulnerabilities"))
    cves = _unique(
        cve.upper()
        for vulnerability in vulnerabilities
        for cve in _cves((_as_mapping(vulnerability) or {}).get("cve"))
    )
    score, _cvss_version = _csaf_score(vulnerabilities)
    severity = _severity_from_score(score)
    ranges: list[AffectedRange] = []
    closed_scopes: list[ClosedScopeEvidence] = []
    remediation_targets: list[str] = []
    remediation_urls: list[str] = []
    for vulnerability in vulnerabilities:
        vuln = _as_mapping(vulnerability)
        if vuln is None:
            continue
        closed_scope = _closed_cisco_scope(
            document,
            product_map=product_map,
            identity_by_pid=identity_by_pid,
            vulnerability=vuln,
            vendor_id=vendor_id,
            source=source,
            fetched_at=fetched_at,
            source_url=source_url,
            license_name=license_name,
        )
        for scope in closed_scope:
            if not any(
                item.model_dump(mode="json") == scope.model_dump(mode="json")
                for item in closed_scopes
            ):
                closed_scopes.append(scope)
        product_status = _as_mapping(vuln.get("product_status")) or {}
        status_map: tuple[tuple[str, str], ...] = (
            ("known_affected", "affected"),
            ("first_affected", "affected"),
            ("known_not_affected", "not_affected"),
            ("fixed", "fixed"),
            ("under_investigation", "under_investigation"),
        )
        for status_key, range_status in status_map:
            for csaf_pid in _as_list(product_status.get(status_key)):
                pid = _text(csaf_pid)
                if pid is None or pid not in product_map:
                    continue
                display_name, version, _family, hardware = product_map[pid]
                if version is None:
                    continue
                canonical_range_product_id, identity = identity_by_pid.get(pid, (product_id, None))
                version_scheme = get_scheme(identity.scheme) if identity else None
                parsed = version_scheme.parse(version) if version_scheme else None
                ranges.append(
                    AffectedRange(
                        advisory_id=advisory_id,
                        product_id=canonical_range_product_id,
                        versions=VersionRange(exact=version, train=parsed.train if parsed else None),
                        hardware_models=[hardware] if hardware else [],
                        status=cast(Any, range_status),
                        fixed_versions=[version] if range_status == "fixed" else [],
                        provenance=[
                            _provenance(
                                source=source,
                                fetched_at=fetched_at,
                                url=source_url,
                                license_name=license_name,
                                field=f"ranges.{display_name}",
                            )
                        ],
                    )
                )
        for remediation in _as_list(vuln.get("remediations")):
            remediation_mapping = _as_mapping(remediation)
            if remediation_mapping is None or _text(remediation_mapping.get("category")) != "vendor_fix":
                continue
            remediation_targets.extend(_version_values(remediation_mapping.get("details")))
            link = _safe_url(remediation_mapping.get("url"))
            if link:
                remediation_urls.append(link)

    remediation = None
    remediation_targets = _sorted_versions(remediation_targets)
    if remediation_targets or remediation_urls:
        remediation = Remediation(
            targets=remediation_targets,
            url=next(iter(_unique(remediation_urls)), None),
        )
    advisory = Advisory(
        id=advisory_id,
        vendor_id=vendor_id,
        title=title,
        published=published,
        updated=updated,
        severity=severity,
        cvss=score,
        cves=cves,
        urls=_unique(urls),
        status=status,
        ranges=ranges,
        closed_scopes=closed_scopes,
        remediation=remediation,
        provenance=[
            _provenance(
                source=source,
                fetched_at=fetched_at,
                url=source_url,
                license_name=license_name,
                field="advisory",
            )
        ],
    )
    vendor_record = resolve_vendor(vendor_id)
    records: list[CanonicalRecord] = []
    if vendor_record is not None:
        records.append(vendor_record.model_copy(update={"provenance": [provenance]}))
    return [*records, *product_records, advisory]


@dataclass(frozen=True)
class GocSafOptions:
    """gocsaf downloader controls selected by the infrastructure image."""

    binary: str = "csaf_downloader"
    worker: int = 2
    rate: str = "0.5"
    client_timeout: str = "30s"
    trusted_only: bool = True
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class CsafValidationResult:
    """Immutable evidence for a gocsaf validation attempt."""

    ok: bool
    raw_sha256: str
    validated_sha256: str | None
    repair: str | None
    detail: str


@dataclass(frozen=True)
class QuarantinedSource:
    url: str
    raw_sha256: str
    reason: str


CsafValidator = Callable[[list[str], Path], int | tuple[int, str]]


def build_csaf_validator_command(binary: str, path: str) -> list[str]:
    """Build the gocsaf validator invocation; no network or mutation flags."""

    if Path(binary).name != "csaf_validator":
        raise ValueError("validator binary must be the software-owned csaf_validator executable")
    return [binary, path]


def _default_csaf_validator(command: list[str], path: Path) -> tuple[int, str]:
    try:
        # Executable and argv are validated by build_csaf_validator_command.
        result = subprocess.run(  # nosec B603
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, type(exc).__name__
    # gocsaf v3.7.1 sets bit 4 when running its local schema validator
    # without a remote service. Some parsing and filename errors appear only
    # as diagnostics, so the exit code alone cannot establish a valid file.
    success_line = f'{json.dumps(str(path))} passes the schema validation.'
    diagnostics = [
        line for line in result.stderr.splitlines()
        if not line.endswith("warn: no remote validator specified")
    ]
    output = result.stdout.strip()
    if result.returncode in (0, 4) and output == success_line and not diagnostics:
        return 0, "local CSAF schema and filename validated"
    detail = "\n".join([output, *diagnostics]).strip()
    return result.returncode or 1, detail[:2000]


def _repair_arista_redundant_ids(content: bytes) -> bytes | None:
    """Drop only the known Arista extension field rejected by gocsaf v3.x."""

    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        return None
    repaired = False
    vulnerabilities: list[Any] = []
    for vulnerability in payload["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            return None
        if "id" not in vulnerability:
            return None
        repaired = True
        vulnerabilities.append({key: value for key, value in vulnerability.items() if key != "id"})
    if not repaired:
        return None
    copy = dict(payload)
    copy["vulnerabilities"] = vulnerabilities
    return json.dumps(copy, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class _CsafValidationMixin:
    validator: CsafValidator
    validator_binary: str
    quarantined: list[QuarantinedSource]
    validation_results: list[CsafValidationResult]

    def _setup_validator(self, validator: CsafValidator | None, validator_binary: str) -> None:
        self.validator = validator or _default_csaf_validator
        self.validator_binary = validator_binary
        self.quarantined = []
        self.validation_results = []

    def validate_document(self, raw: RawDocument, *, path: Path | None = None) -> CsafValidationResult:
        raw_hash = hashlib.sha256(raw.content).hexdigest()
        own_directory = tempfile.TemporaryDirectory(prefix="osak-csaf-validate-") if path is None else None
        repair_directory: tempfile.TemporaryDirectory[str] | None = None
        if path is None:
            if own_directory is None:
                raise ConnectorFetchError("failed to allocate CSAF validation directory")
            validation_path = Path(own_directory.name) / (Path(urlparse(raw.url).path).name or "advisory.json")
        else:
            validation_path = path
        try:
            validation_path.parent.mkdir(parents=True, exist_ok=True)
            validation_path.write_bytes(raw.content)
            command = build_csaf_validator_command(self.validator_binary, str(validation_path))
            response = self.validator(command, validation_path)
            return_code, detail = response if isinstance(response, tuple) else (response, "")
            if return_code == 0:
                result = CsafValidationResult(True, raw_hash, raw_hash, None, "validated")
                self.validation_results.append(result)
                return result

            # A gocsaf v3.x validator rejects Arista's redundant vulnerabilities[].id
            # extension. Only this exact structural repair is permitted, and the
            # transformed bytes are validated again before acceptance.
            repair = _repair_arista_redundant_ids(raw.content) if "arista.com" in raw.url else None
            known_error = "additional propert" in detail.lower() and "id" in detail.lower()
            if repair is not None and known_error:
                # Keep the provider's canonical basename so gocsaf's filename
                # check is meaningful; the untouched raw path is never replaced.
                repair_directory = tempfile.TemporaryDirectory(prefix="osak-csaf-repair-")
                repaired_path = Path(repair_directory.name) / validation_path.name
                repaired_path.write_bytes(repair)
                repair_command = build_csaf_validator_command(self.validator_binary, str(repaired_path))
                repair_response = self.validator(repair_command, repaired_path)
                repair_code, repair_detail = (
                    repair_response if isinstance(repair_response, tuple) else (repair_response, "")
                )
                if repair_code == 0:
                    result = CsafValidationResult(
                        True,
                        raw_hash,
                        hashlib.sha256(repair).hexdigest(),
                        "removed vulnerabilities[].id",
                        "validated repaired copy; raw document retained unchanged",
                    )
                    self.validation_results.append(result)
                    return result
                detail = repair_detail or detail or "repaired CSAF failed validation"
            reason = detail or "gocsaf validator rejected CSAF document"
            result = CsafValidationResult(False, raw_hash, None, None, reason)
            self.validation_results.append(result)
            self.quarantined.append(QuarantinedSource(raw.url, raw_hash, reason))
            return result
        finally:
            if own_directory is not None:
                own_directory.cleanup()
            if repair_directory is not None:
                repair_directory.cleanup()


def build_csaf_command(
    options: GocSafOptions,
    *,
    output_dir: str,
    provider_url: str,
    since: datetime | None = None,
) -> list[str]:
    if Path(options.binary).name != "csaf_downloader":
        raise ValueError("downloader binary must be the software-owned csaf_downloader executable")
    command = [
        options.binary,
        "--directory",
        output_dir,
        "--worker",
        str(options.worker),
        "--rate",
        options.rate,
        "--client_timeout",
        options.client_timeout,
    ]
    if options.trusted_only:
        command.append("--trusted_only")
    if since is not None:
        command.extend(["--time_range=" + since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")])
    command.extend(options.extra_args)
    command.append(provider_url)
    return command


def _default_gocsaf_runner(command: list[str], output_dir: Path) -> None:
    try:
        # Executable and argv are validated by build_csaf_command.
        subprocess.run(  # nosec B603
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=15 * 60,
            cwd=output_dir,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConnectorFetchError("gocsaf downloader failed") from exc
