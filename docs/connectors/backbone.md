# Backbone connector handoff

This workstream contains passive structured-fact connectors for the four v1
backbone sources. The classes are deliberately not registered in
`pyproject.toml`; the parent integration owns that file and can copy the table
below into the `osak.connectors` entry-point group.

| Entry-point name | Import path | Kind | Fetch behavior | Normalized records |
| --- | --- | --- | --- | --- |
| `cvelistv5` | `osak.connectors.cvelistv5:CveListV5Connector` | advisory | `since=None` streams the official daily GitHub release baseline ZIP; a cursor consumes `cves/deltaLog.json` inclusively; cursors older than the delta retention fall back to a fresh baseline | `Vendor`, `Product`, `Advisory` with affected ranges, source links, remediation targets and provenance |
| `cisa_kev` | `osak.connectors.cisa_kev:CisaKevConnector` | enrichment | full catalog JSON (the feed is a snapshot, so `since` is intentionally idempotent) | `Enrichment(kev, kev_date, ransomware)` |
| `first_epss` | `osak.connectors.first_epss:FirstEpssConnector` | enrichment | daily compressed CSV for scheduled bulk refresh; `fetch_for_cves()` / `fetch_cves()` uses the bounded FIRST API for cache misses | `Enrichment(epss, percentile, epss_date)` |
| `nvd` | `osak.connectors.nvd:NvdConnector` | enrichment | incremental `lastModStartDate`/`lastModEndDate` requests (split into NVD's maximum 120-day windows), `startIndex` pagination and documented key/no-key pacing | `Enrichment(cvss, cvss_version, cpes)` |

Aliases are available for discovery integrations that prefer uppercase source
names: `CVEListV5Connector`, `KEVConnector`, `EPSSConnector`, and
`NVDConnector`.

## Hosted vendor coverage

The CT203 production profile sets `OSAK_VENDOR_SCOPE=cisco,fortinet,arista`.
The CVE worker reuses its official daily archive and records applicable
entries for these vendors before switching to deltas. NVD requests are
filtered to the registered publisher identifiers and retain their cursor
and rate limits. The EPSS worker keeps scores for locally tracked CVEs. The
hosted matcher and offline export are intended for
these three vendors. Previously imported history can still appear in
the catalog. Set the scope explicitly before the first import on a new
installation.

## Source and safety boundaries

- The source URL, fetch time, license and field are retained in every emitted
  `Provenance` object.
- CVE, KEV, EPSS and NVD descriptions, required-action prose, exploit links,
  payloads and customer inventory are not emitted as canonical fields.
- An explicit CNA `defaultStatus` is retained per affected product/range and
  is used by matching only when every range for that product is interpretable;
  a missing `defaultStatus` is never inferred. Unparseable ranges are kept as
  `under_investigation` so they block a fail-open fallback.
- CVE references are restricted to CVE/vendor-advisory links; links tagged as
  exploit, POC or payload are discarded.
- The NVD API key is sent as an `apiKey` header only. It is never put in a
  request URL or provenance URL.
- Every fetch is replay-safe. In particular, CVE delta processing includes the
  cursor timestamp (`>=`) and deduplicates repeated CVE IDs before fetching.

## Persistence handoff to ingest/core

The worker should persist the connector cursor only after all yielded raw
documents have been normalized and merged. Use a source-level cursor for
`cvelistv5` containing the highest successfully processed delta `fetchTime`;
inclusive replay is expected and canonical upserts must therefore be
idempotent by record ID. If the cursor predates the retained delta log, the
connector yields a complete baseline snapshot and the worker should replace
or reconcile the existing snapshot before advancing the cursor.

Persist raw CVE archive members and JSON pages content-hashed and immutable,
but do not persist the in-memory `Asset` request models here. Enrichment rows
are keyed by `cve_id`, with field-level provenance merged rather than silently
overwritten. For CVE records, persist emitted `Vendor` and `Product` records
before `Advisory.ranges` so foreign-key-backed stores can upsert them in one
transaction.
