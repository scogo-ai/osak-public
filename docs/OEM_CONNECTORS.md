# OEM connector map

The parent package registers these classes as `osak.connectors` entry points.
The implementation is intentionally read-only: connectors return immutable
source bytes to ingestion and normalize structured identifiers, dates, scores,
versions, ranges, fixes, and links. Vendor prose, exploit payloads, and target
inventory are not copied into canonical records.

| Entry point | Class | Source route | Auth | Poll |
|---|---|---|---|---:|
| `cisco_openvuln` | `osak.connectors.cisco:CiscoOpenVulnConnector` | `https://apix.cisco.com/security/advisories/v2` (incremental `all/lastpublished`; optional publisher-configured `OSType` queries) | OAuth client credentials | 15m |
| `cisco_csaf` | `osak.connectors.cisco:CiscoCsafConnector` | Cisco `/.well-known/csaf/provider-metadata.json` via `csaf_downloader` | none | 15m |
| `fortinet_psirt_rss` | `osak.connectors.fortinet:FortinetRssConnector` | `https://www.fortiguard.com/rss/ir.xml` | none | 15m |
| `fortinet_cna` | `osak.connectors.fortinet:FortinetCnaConnector` | CVE List V5 raw records supplied by the backbone | none | backbone |
| `fortinet_psirt_page` | `osak.connectors.fortinet:FortinetAdvisoryPageConnector` | `https://fortiguard.fortinet.com/psirt/FG-IR-*` | none | on demand |
| `arista_csaf` | `osak.connectors.arista:AristaCsafConnector` | Arista advisory index → per-advisory CSAF JSON | none | 30m |
| `cisco_eox` | `osak.connectors.cisco:CiscoEoxConnector` | Optional lifecycle feed, enabled explicitly by an entitled operator. EoX v5 `EOXByDates` pages use `UPDATE_TIMESTAMP` | OAuth client credentials | daily |
| `cisco_asa_compatibility` | `osak.connectors.cisco_asa_compat:CiscoAsaCompatibilityConnector` | Cisco ASA compatibility matrix, ASA 9.23/9.22 table | none | daily |
| `endoflife_date_fortios` | `osak.connectors.eol:EndOfLifeDateConnector` | `https://endoflife.date/api/v1/products/fortios/` | none | daily |

The parent `pyproject.toml` should register the classes with factories that
return a connector instance, for example:

```toml
[project.entry-points."osak.connectors"]
cisco_openvuln = "osak.connectors.cisco:CiscoOpenVulnConnector"
cisco_csaf = "osak.connectors.cisco:CiscoCsafConnector"
fortinet_psirt_rss = "osak.connectors.fortinet:FortinetRssConnector"
fortinet_cna = "osak.connectors.fortinet:FortinetCnaConnector"
fortinet_psirt_page = "osak.connectors.fortinet:FortinetAdvisoryPageConnector"
arista_csaf = "osak.connectors.arista:AristaCsafConnector"
cisco_eox = "osak.connectors.cisco:CiscoEoxConnector"
cisco_asa_compatibility = "osak.connectors.cisco_asa_compat:CiscoAsaCompatibilityConnector"
endoflife_date_fortios = "osak.connectors.eol:EndOfLifeDateConnector"
```

`fortinet_cna` is a normalizer adapter, not an independent poller. Its
`healthcheck()` is unavailable until the CVE List V5 backbone supplies the raw
record; this prevents an empty query path from being reported as coverage.

During the existing Arista index → advisory-page → CSAF crawl, HTML page
facts are normalized with `arista_psirt_page` field provenance. The page path
emits
only an explicitly stated introduced EOS release plus vendor-structured
configuration conditions when the page establishes EOS/platform scope. The
two documented configuration alternatives are represented as reviewed parsed
features; missing one keeps matching unknown rather than clearing a finding.
It does not infer later affected releases, clear products listed as not
affected, or manufacture fixes; the CSAF connector remains the independent
source for expected applicability labels and strict validation.

## Credentials and source terms

Cisco connectors read credentials from constructor arguments or, by default,
the process environment: `CISCO_OPENVULN_ACCESS_TOKEN`, `CISCO_CLIENT_ID`,
`CISCO_CLIENT_SECRET`, and `CISCO_EOX_ACCESS_TOKEN`. Values are held only in
memory and are never included in a persisted `RawDocument` URL or error.
Cisco API/CSAF/EoX terms are marked `review` until Scogo confirms entitlement
and derived-data redistribution rights. FortiGuard and Arista page/CSAF data
are marked `restricted`/`review`; only structured facts plus links should be
served. Fortinet CNA records are CVE List V5 data and retain CVE attribution.
The endoflife.date lifecycle source is MIT-licensed, with attribution.

The EoX normal entry point uses only date windows and pagination; it does not
send product IDs, serials, or inventory strings. OpenVuln uses the persisted
`since` cursor as an inclusive `lastpublished` date window. Software Checker
queries are separate, explicit publisher configuration (`CiscoSoftwareCheckerQuery`)
for supported release checks; they are not inferred from caller inventory.

## gocsaf validation and quarantine

Cisco downloads use `csaf_downloader` with `--trusted_only`, bounded workers,
rate and client timeout. Each downloaded document is then checked by
`csaf_validator`; a failed document is quarantined and reported by
`healthcheck()` with its URL and raw SHA-256, never silently normalized.

Arista's published CSAF has a known gocsaf v3.x schema incompatibility:
`vulnerabilities[].id` is an extra property. The connector retains the raw
bytes and hash, removes only that field in a temporary transformed copy, and
accepts the document only when the transformed copy passes the same validator.
Any other validation error, or a failed repair validation, remains quarantined.

The infra image must pin and report its gocsaf version (the tested stable
line is v3.7.1) and provide `csaf_downloader` plus `csaf_validator`. The
connector does not contact customer targets or execute source-provided data.

## Verification boundary

Bounded checks against public sources on 2026-11-27 established:

- Fortinet RSS returned XML and the one-item page fallback returned HTML; both
  normalized to structured advisory records. A live CVE List V5 Fortinet CNA
  record also normalized, while the CNA adapter correctly reports that polling
  is owned by the backbone and does not claim independent coverage.
- endoflife.date returned one FortiOS lifecycle document and normalized eight
  release records.
- Cisco openVuln and EoX returned HTTP 403 without credentials. The connectors
  report unavailable/empty rather than claiming success. EoX also reports
  unavailable when no product/software query is configured.
- The Arista index endpoint returned an anti-bot challenge in the bounded
  check, so no automatic index coverage is claimed. A separately bounded
  public advisory-page → CSAF check fetched SA 0162; gocsaf quarantined the
  raw document because its filename does not match the CSAF tracking id.
  The raw SHA-256 is retained in the validation fixture. The mock contract
  test exercises the complete index → advisory page → CSAF chain.


## Cisco release checks

On an empty database openVuln pages through the complete `/all` catalog. Subsequent polls use `/all/lastpublished` with inclusive dates. The maximum page size is 100. If a credential is missing or rejected, the worker records a failed poll without advancing the cursor.

The supported query families are `ios`, `iosxe`, `nxos`, `asa`, `fmc`, `ftd` and `fxos`. Each query identifies the catalog product for its release and platform evidence. FMC, FTD and FXOS have no ordering scheme in v1, so train comparisons for these products remain unknown.

Four additional release checks were verified against Cisco's published version catalogs on 27 November 2026. IOS 15.1(2)SG3 returned 71 advisories, FMC 7.4.1 returned 28, FTD 7.2.0 on FPR2100 returned 98 and FXOS 2.10.1.159 on FPR9000 returned eight. The same catalog also lists FXOS 2.17.0.537 on FPR4100. Cisco returned `NO_DATA_FOUND` for that lookup. An empty first result adds no ranges and polling continues to the next configured release.

Set `OSAK_CISCO_CHECKER_QUERIES` in the worker environment to a JSON array of public software release queries. For example, `[{"os_type":"nxos","version":"9.3(10)","platform_alias":"NEXUS9000"}]` requests a published Nexus release. The connector follows the same API pagination for these responses. Choose versions from the publisher catalog. Caller asset identifiers and inventory strings never enter this setting. [Cisco Software Checker reference](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/)
