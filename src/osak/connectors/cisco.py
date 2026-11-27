"""Cisco openVuln, CSAF and EoX connector implementations."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal
from urllib.parse import quote, urljoin

import httpx

from osak.connectors.base import HealthStatus, RawDocument
from osak.connectors.oem_common import (
    ConnectorFetchError,
    CsafValidator,
    GocSafOptions,
    GocSafRunner,
    PublisherHTTPError,
    _as_list,
    _as_mapping,
    _catalog_records,
    _CsafValidationMixin,
    _cves,
    _default_gocsaf_runner,
    _HttpConnector,
    _json,
    _license,
    _now,
    _number,
    _parse_date,
    _parse_datetime,
    _provenance,
    _safe_url,
    _severity_from_score,
    _severity_from_value,
    _sorted_versions,
    _text,
    _unique,
    _version_values,
    build_csaf_command,
    normalize_csaf,
)
from osak.core.catalog import resolve_product
from osak.core.models import (
    Advisory,
    AffectedRange,
    CanonicalRecord,
    EoLRecord,
    Remediation,
    VersionRange,
)


class CiscoCsafConnector(_CsafValidationMixin, _HttpConnector):
    id: ClassVar[str] = "cisco_csaf"
    vendor_scope: ClassVar[list[str]] = ["cisco"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["none"]] = "none"
    rate_limit: ClassVar[str] = "provider-defined; gocsaf rate applies"
    schedule: ClassVar[int] = 900
    provider_url: ClassVar[str] = "https://www.cisco.com/.well-known/csaf/provider-metadata.json"

    def __init__(
        self,
        *,
        options: GocSafOptions | None = None,
        runner: GocSafRunner | None = None,
        validator: CsafValidator | None = None,
        validator_binary: str = "csaf_validator",
        timeout: float = 30.0,
    ) -> None:
        super().__init__(allowed_hosts={"www.cisco.com"}, timeout=timeout)
        self.options = options or GocSafOptions()
        self.runner = runner or _default_gocsaf_runner
        self._setup_validator(validator, validator_binary)
        self.license = _license(
            "Cisco PSIRT CSAF terms pending",
            "https://www.cisco.com/.well-known/csaf/provider-metadata.json",
            "Cisco PSIRT; structured facts and source links only. Review Cisco terms before redistribution.",
            "review",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        with tempfile.TemporaryDirectory(prefix="osak-csaf-") as directory:
            output_dir = Path(directory)
            command = build_csaf_command(
                self.options,
                output_dir=directory,
                provider_url=self.provider_url,
                since=since,
            )
            self.runner(command, output_dir)
            documents: list[RawDocument] = []
            for path in sorted(output_dir.rglob("*.json")):
                relative = path.relative_to(output_dir)
                if path.name == "provider-metadata.json":
                    continue
                try:
                    content = path.read_bytes()
                except OSError as exc:
                    raise ConnectorFetchError("gocsaf output could not be read") from exc
                source_url = urljoin("https://www.cisco.com/.well-known/csaf/", str(relative))
                documents.append(
                    RawDocument(
                        url=source_url,
                        fetched_at=_now(),
                        content=content,
                        media_type="application/json",
                    )
                )
                self.validate_document(documents[-1], path=path)
                if not self.validation_results[-1].ok:
                    documents.pop()
            return documents

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        document = _json(raw.content)
        if not isinstance(document, Mapping):
            return []
        return normalize_csaf(
            document,
            source=self.id,
            source_url=raw.url,
            fetched_at=raw.fetched_at,
            vendor_id="cisco",
            vendor_name="Cisco",
            product_id="cisco-iosxe",
            product_family="Cisco IOS XE Software",
            scheme="cisco_iosxe",
            license_name=self.license.name,
        )

    def healthcheck(self) -> HealthStatus:
        if shutil.which(self.options.binary) is None:
            return HealthStatus(available=False, detail="gocsaf downloader is not installed")
        if shutil.which(self.validator_binary) is None:
            return HealthStatus(available=False, detail="gocsaf csaf_validator is not installed")
        if self.quarantined:
            return HealthStatus(
                available=False,
                detail=f"{len(self.quarantined)} Cisco CSAF document(s) quarantined: {self.quarantined[-1].reason}",
            )
        return HealthStatus(available=True, detail="gocsaf downloader is available")


@dataclass(frozen=True)
class CiscoSoftwareCheckerQuery:
    """Publisher-configured Cisco Software Checker release query."""

    os_type: str
    version: str
    platform_alias: str | None = None


class _CiscoOAuthMixin:
    token_url: ClassVar[str] = "https://id.cisco.com/oauth2/default/v1/token"
    access_token: str | None
    client_id: str | None
    client_secret: str | None
    client: httpx.Client | None
    timeout: float
    _clock: Callable[[], float]
    _explicit_access_token: bool
    _expires_at: float | None

    if TYPE_CHECKING:
        def _get(self, url: str, *, headers: Mapping[str, str] | None = None) -> RawDocument: ...

    def _init_oauth(
        self,
        *,
        access_token: str | None,
        client_id: str | None,
        client_secret: str | None,
        env_token: str,
        clock: Callable[[], float] | None = None,
    ) -> None:
        configured_token = access_token or os.getenv(env_token)
        self.access_token = configured_token
        self.client_id = client_id or os.getenv("CISCO_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("CISCO_CLIENT_SECRET")
        self._explicit_access_token = configured_token is not None
        self._expires_at = None
        self._clock = clock or time.monotonic

    def _token(self, *, force: bool = False) -> str | None:
        if force:
            self.access_token = None
            self._expires_at = None
            self._explicit_access_token = False
        if self.access_token:
            if (
                not self._explicit_access_token
                and self._expires_at is not None
                and self._clock() >= self._expires_at - 60
            ):
                self.access_token = None
                self._expires_at = None
            else:
                return self.access_token
        if not self.client_id or not self.client_secret:
            return None
        own_client = self.client is None
        client = self.client or httpx.Client(timeout=self.timeout, follow_redirects=True)
        try:
            response = client.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            if response.status_code >= 400:
                return None
            value = response.json()
            if isinstance(value, Mapping) and isinstance(value.get("access_token"), str):
                self.access_token = value["access_token"]
                expires_in = value.get("expires_in")
                if isinstance(expires_in, (int, float)) and expires_in > 0:
                    self._expires_at = self._clock() + float(expires_in)
                else:
                    self._expires_at = None
                self._explicit_access_token = False
                return self.access_token
            return None
        except (httpx.HTTPError, ValueError):
            return None
        finally:
            if own_client:
                client.close()

    def _auth_get(self, url: str) -> RawDocument:
        token = self._token()
        if token is None:
            raise ConnectorFetchError("Cisco credentials unavailable")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            return self._get(url, headers=headers)
        except PublisherHTTPError as exc:
            if exc.status != 401:
                raise
            refreshed = self._token(force=True)
            if refreshed is None:
                raise
            return self._get(
                url, headers={"Authorization": f"Bearer {refreshed}", "Accept": "application/json"}
            )


def _last_page(payload: Mapping[str, Any]) -> int | None:
    pagination = _as_mapping(payload.get("PaginationResponseRecord")) or _as_mapping(
        payload.get("pagination")
    )
    if pagination is None:
        return None
    for key in ("LastIndex", "lastIndex", "lastPage", "last_page", "totalPages", "total_pages"):
        value = pagination.get(key)
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.isdigit() and int(value) > 0:
            return int(value)
    return None


class CiscoOpenVulnConnector(_CiscoOAuthMixin, _HttpConnector):
    id: ClassVar[str] = "cisco_openvuln"
    vendor_scope: ClassVar[list[str]] = ["cisco"]
    kind: ClassVar[Literal["advisory"]] = "advisory"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["oauth_client_credentials"]] = "oauth_client_credentials"
    rate_limit: ClassVar[str] = "Cisco API Console quota"
    schedule: ClassVar[int] = 900
    base_url: ClassVar[str] = "https://apix.cisco.com/security/advisories/v2"

    def __init__(
        self,
        *,
        access_token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        software_checker_queries: Sequence[CiscoSoftwareCheckerQuery] | None = None,
        page_size: int = 100,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(allowed_hosts={"apix.cisco.com", "id.cisco.com"}, timeout=timeout, client=client)
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        # These are environment variable names, not secret values.
        self._init_oauth(  # nosec B106
            access_token=access_token,
            client_id=client_id,
            client_secret=client_secret,
            env_token="CISCO_OPENVULN_ACCESS_TOKEN",  # nosec B106
            clock=clock,
        )
        if software_checker_queries is None:
            configured = json.loads(os.getenv("OSAK_CISCO_CHECKER_QUERIES") or "[]")
            if not isinstance(configured, list):
                raise ValueError("OSAK_CISCO_CHECKER_QUERIES must be a JSON array")
            software_checker_queries = [CiscoSoftwareCheckerQuery(**query) for query in configured]
        self.software_checker_queries = tuple(software_checker_queries)
        self.page_size = page_size
        self.license = _license(
            "Cisco PSIRT openVuln API terms pending",
            "https://github.com/CiscoPSIRT/openVulnAPI/blob/master/LICENSE.md",
            "Cisco PSIRT openVuln; structured facts and source links only. Confirm API terms before redistribution.",
            "review",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        if self._token() is None:
            raise ConnectorFetchError("Cisco PSIRT credentials unavailable")
        endpoint = f"{self.base_url}/all"
        parameters = {"summaryDetails": "false", "productNames": "true"}
        if since is not None:
            endpoint += "/lastpublished"
            parameters.update(startDate=since.astimezone(UTC).date().isoformat(), endDate=_now().date().isoformat())
        yield from self._advisory_pages(endpoint, parameters)
        for query in self.software_checker_queries:
            options = {"version": query.version}
            if query.platform_alias:
                options["platformAlias"] = query.platform_alias
            yield from self._advisory_pages(
                f"{self.base_url}/OSType/{quote(query.os_type, safe='')}", options
            )

    def _advisory_pages(self, endpoint: str, parameters: dict[str, str]) -> Iterable[RawDocument]:
        page = 1
        seen: set[tuple[str, ...]] = set()
        while True:
            url = str(httpx.URL(endpoint, params={**parameters, "pageIndex": page, "pageSize": self.page_size}))
            try:
                document = self._auth_get(url)
            except PublisherHTTPError as exc:
                # An empty release lookup or publication window produces no
                # applicability evidence. A missing continuation page is an error.
                filtered_query = "version" in parameters or endpoint.endswith("/all/lastpublished")
                if page == 1 and filtered_query and exc.no_data_found:
                    return
                raise
            payload = _json(document.content)
            if not isinstance(payload, Mapping) or not isinstance(payload.get("advisories"), list):
                raise ConnectorFetchError("Cisco advisory list response is malformed")
            ids = tuple(item["advisoryId"] for item in payload["advisories"]
                        if isinstance(item, Mapping) and isinstance(item.get("advisoryId"), str))
            if ids and ids in seen:
                raise ConnectorFetchError("Cisco repeated an advisory page")
            seen.add(ids)
            yield document
            paging = payload.get("paging")
            if isinstance(paging, Mapping) and "next" in paging:
                more = paging["next"] not in (None, "", "NA")
            else:
                last_page = _last_page(payload)
                more = page < last_page if last_page is not None else len(payload["advisories"]) == self.page_size
            if not more:
                break
            if not payload["advisories"]:
                raise ConnectorFetchError("Cisco returned an empty page before the last page")
            page += 1

    @staticmethod
    def _checker_context(url: str) -> tuple[str | None, str | None, str | None]:
        parsed = httpx.URL(url)
        parts = parsed.path.split("/")
        try:
            index = parts.index("OSType")
        except ValueError:
            return None, None, None
        os_type = parts[index + 1] if index + 1 < len(parts) else None
        return os_type, parsed.params.get("version"), parsed.params.get("platformAlias")

    @staticmethod
    def _platform_matches(platform_name: str, alias: str) -> bool:
        tokens = {
            "fpr2100": "firepower 2100",
            "fpr4100": "firepower 4100",
            "fwl3100": "secure firewall 3100",
            "nexus9000": "nexus 9000",
            "nexus3000": "nexus 3000",
        }
        return tokens.get(alias.casefold(), alias).casefold() in platform_name.casefold()

    @staticmethod
    def _platform_first_fixed(platform: Mapping[str, Any]) -> list[str]:
        values: list[str] = []
        for item in _as_list(platform.get("firstFixes")) or _as_list(platform.get("firstFixed")):
            mapping = _as_mapping(item)
            if mapping is not None:
                values.extend(_version_values(mapping.get("name") or mapping.get("version")))
            else:
                values.extend(_version_values(item))
        return values

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = _json(raw.content)
        if isinstance(payload, list):
            advisories = payload
        else:
            advisories = _as_list(payload.get("advisories")) or _as_list(payload.get("advisory"))
        checker_os, checker_version, checker_platform = self._checker_context(raw.url)
        checker_product = resolve_product("cisco", checker_os) if checker_os else None
        records: list[CanonicalRecord] = _catalog_records(
            vendor_id="cisco",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
            product_names=[checker_os] if checker_os else (),
        )
        for item in advisories:
            mapping = _as_mapping(item)
            if mapping is None:
                continue
            advisory_id = _text(mapping.get("advisoryId")) or _text(mapping.get("advisory_id"))
            if not advisory_id:
                continue
            first_fixed = _sorted_versions(
                _version_values(
                    mapping.get("firstFixed")
                    or mapping.get("firstFixedVersion")
                    or mapping.get("firstFixedRelease")
                )
            )
            score = _number(mapping.get("cvssBaseScore", mapping.get("cvss")))
            severity = _severity_from_value(mapping.get("sir") or mapping.get("severity"))
            if severity == "unknown":
                severity = _severity_from_score(score)
            cves = _cves(mapping.get("cves") or mapping.get("cve"))
            urls = [
                link
                for link in (
                    _safe_url(mapping.get("csafUrl")),
                    _safe_url(mapping.get("publicationUrl")),
                )
                if link
            ]
            ranges: list[AffectedRange] = []
            if checker_version and checker_product is not None:
                product_id = checker_product.id
                evidence = [_provenance(source=self.id, fetched_at=raw.fetched_at, url=raw.url,
                                        license_name=self.license.name, field="ranges")]
                platform_rows = [r for r in _as_list(mapping.get("platforms"))
                                 if isinstance(r, Mapping) and isinstance(r.get("name"), str)]
                for platform in platform_rows:
                    name = platform["name"]
                    if checker_platform and len(platform_rows) != 1 and not self._platform_matches(name, checker_platform):
                        continue
                    state = str(platform.get("vulnerabilityState", "")).casefold().replace(" ", "")
                    scoped_fixed = _sorted_versions(self._platform_first_fixed(platform))
                    status: Literal["affected", "not_affected", "under_investigation"] = "under_investigation"
                    if state == "vulnerable":
                        status = "affected"
                    elif state in {"notvulnerable", "notaffected"}:
                        status = "not_affected"
                    models = [name, checker_platform] if checker_platform else [name]
                    ranges.append(AffectedRange(
                        advisory_id=advisory_id, product_id=product_id, versions=VersionRange(exact=checker_version),
                        status=status, hardware_models=models, fixed_versions=scoped_fixed, provenance=evidence,
                    ))
                    for fixed in scoped_fixed:
                        ranges.append(AffectedRange(
                            advisory_id=advisory_id, product_id=product_id, versions=VersionRange(exact=fixed),
                            status="fixed", hardware_models=models, provenance=evidence,
                        ))
                hardware = [checker_platform] if checker_platform else []
                if not platform_rows:
                    ranges.append(AffectedRange(
                        advisory_id=advisory_id, product_id=product_id, versions=VersionRange(exact=checker_version),
                        status="affected", hardware_models=hardware, fixed_versions=first_fixed, provenance=evidence,
                    ))
                for fixed in first_fixed:
                    ranges.append(AffectedRange(
                        advisory_id=advisory_id, product_id=product_id, versions=VersionRange(exact=fixed),
                        status="fixed", hardware_models=hardware, provenance=evidence,
                    ))
            # The publisher's "version" field is a bulletin revision, not an affected release.
            remediation = Remediation(targets=first_fixed) if first_fixed else None
            records.append(
                Advisory(
                    id=advisory_id,
                    vendor_id="cisco",
                    title=_text(mapping.get("advisoryTitle")) or advisory_id,
                    published=_parse_datetime(
                        mapping.get("firstPublished") or mapping.get("first_published")
                    ),
                    updated=_parse_datetime(
                        mapping.get("lastUpdated") or mapping.get("last_updated")
                    ),
                    severity=severity,
                    cvss=score,
                    cves=cves,
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
            )
        return records

    def healthcheck(self) -> HealthStatus:
        if self._token() is None:
            return HealthStatus(available=False, detail="Cisco openVuln credentials unavailable")
        return HealthStatus(available=True, detail="Cisco openVuln credentials configured")


class CiscoEoxConnector(_CiscoOAuthMixin, _HttpConnector):
    requires_opt_in: ClassVar[bool] = True
    id: ClassVar[str] = "cisco_eox"
    vendor_scope: ClassVar[list[str]] = ["cisco"]
    kind: ClassVar[Literal["eol"]] = "eol"
    tier: ClassVar[Literal["free"]] = "free"
    auth: ClassVar[Literal["oauth_client_credentials"]] = "oauth_client_credentials"
    rate_limit: ClassVar[str] = "Cisco Support API quota"
    schedule: ClassVar[int] = 86400
    base_url: ClassVar[str] = "https://apix.cisco.com/supporttools/eox/rest/5"

    def __init__(
        self,
        *,
        access_token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        bootstrap_days: int = 30,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(allowed_hosts={"apix.cisco.com"}, timeout=timeout, client=client)
        if bootstrap_days < 1:
            raise ValueError("bootstrap_days must be positive")
        # These are environment variable names, not secret values.
        self._init_oauth(  # nosec B106
            access_token=access_token,
            client_id=client_id,
            client_secret=client_secret,
            env_token="CISCO_EOX_ACCESS_TOKEN",  # nosec B106
            clock=clock,
        )
        self.bootstrap_days = bootstrap_days
        self.license = _license(
            "Cisco Support API EoX terms pending",
            "https://developer.cisco.com/docs/support-apis/eox/",
            "Cisco Support APIs EoX; structured lifecycle facts and source links only. Confirm entitlement and terms.",
            "review",
        )

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        if self._token() is None:
            raise ConnectorFetchError("Cisco EoX credentials unavailable")
        start = (since or (_now() - timedelta(days=self.bootstrap_days))).astimezone(UTC).date().isoformat()
        end = _now().date().isoformat()
        documents: list[RawDocument] = []
        for page in range(1, 201):
            request_url = (
                f"{self.base_url}/EOXByDates/{page}/{start}/{end}"
                "?responseencoding=json&eoxAttrib=UPDATE_TIMESTAMP"
            )
            fetched = self._auth_get(request_url)
            documents.append(fetched)
            payload = _json(fetched.content)
            if not isinstance(payload, Mapping):
                break
            last_page = _last_page(payload)
            if last_page is None or page >= last_page:
                break
        return documents

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        payload = _json(raw.content)
        if not isinstance(payload, Mapping):
            return []
        records: list[CanonicalRecord] = _catalog_records(
            vendor_id="cisco",
            source=self.id,
            fetched_at=raw.fetched_at,
            url=raw.url,
            license_name=self.license.name,
        )
        for item in _as_list(payload.get("EOXRecord")):
            mapping = _as_mapping(item)
            if mapping is None:
                continue
            product_id = _text(mapping.get("EOLProductID"))
            if not product_id:
                continue
            record_mapping: Mapping[str, Any] = mapping

            def milestone(*names: str, _record: Mapping[str, Any] = record_mapping) -> date | None:
                for name in names:
                    value = _record.get(name)
                    if isinstance(value, Mapping):
                        parsed = _parse_date(value.get("value"))
                    else:
                        parsed = _parse_date(value)
                    if parsed is not None:
                        return parsed
                return None

            records.append(
                EoLRecord(
                    id=f"cisco-eox:{product_id}",
                    vendor_id="cisco",
                    product_id="cisco_hardware",
                    model=product_id,
                    eos=milestone("EndOfSaleDate"),
                    end_maintenance=milestone("EndOfSWMaintenanceReleases"),
                    end_security=milestone("EndOfSecurityVulSupportDate"),
                    last_support=milestone("LastDateOfSupport", "EndOfLastSupportDate"),
                    provenance=[
                        _provenance(
                            source=self.id,
                            fetched_at=raw.fetched_at,
                            url=raw.url,
                            license_name=self.license.name,
                            field="eol",
                        )
                    ],
                )
            )
        return records

    def healthcheck(self) -> HealthStatus:
        if self._token() is None:
            return HealthStatus(available=False, detail="Cisco EoX credentials unavailable")
        return HealthStatus(
            available=True, detail="Cisco EoX credentials configured for paged date sync"
        )
