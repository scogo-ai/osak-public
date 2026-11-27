# Connector interfaces and operations

An OSAK connector describes one data source. The scheduler discovers installed packages in the `osak.connectors` Python entry-point group. The entry-point name must match the connector's stable ID. A duplicate ID makes discovery fail so two sources cannot overwrite each other's cursor.

| Field | Meaning |
|---|---|
| `vendor_scope` | Canonical vendor IDs, or `*` for a cross-vendor source |
| `kind` | Advisory, enrichment or lifecycle data |
| `tier` and `auth` | Free/paid and the source's authentication method |
| `license` | Source terms URL, attribution and public redistribution decision |
| `rate_limit` and `schedule` | Publisher request limits and successful poll interval in seconds |

`fetch(since)` produces bounded raw documents with the publisher URL, observation time, media type and bytes. The initial poll must be able to establish a baseline. Later polls must recover from downtime longer than the upstream delta window. Rate limits, invalid upstream responses and missing credentials must remain visible as source status.

`normalize(raw)` yields canonical records. A record can carry explicit affected, fixed, unaffected and under-investigation evidence. Keep hardware and release constraints attached to the record they qualify. Preserve per-field source references when merging. A CVE's assigning organization can differ from the vendor responsible for an affected product.

`healthcheck()` describes whether a connector can run with its current environment. Health and the timestamp of the last successful sync answer different questions. The public sources endpoint needs both to explain which evidence is available.

## Run a poll

Use `docker compose exec worker osak ingest --help` for worker options. To poll one source and publish a snapshot immediately, use `docker compose exec worker osak ingest --once --source cisa_kev --export`. Source status, the export manifest and the digest identify what was successfully published.

## V1 sources

| Source | Baseline and changes | Use |
|---|---|---|
| CVE List V5 | Official repository snapshot and timestamped deltas | CNA product identities, ranges, solutions and linked CVEs |
| CISA KEV | Full catalog every hour | Catalog membership and date added |
| FIRST EPSS | Daily scores, per-CVE API for bounded lookups | Probability, percentile and model date |
| NVD | Initial mirror followed by modified-date windows with pagination | CPE and CVSS enrichment |
| Cisco openVuln and CSAF | Software Checker, advisory deltas and published CSAF | Product/version verdict evidence, fixes and advisory revisions |
| Fortinet PSIRT | RSS notifications, vendor pages and Fortinet CNA entries | FortiOS affected tables and fix targets |
| Arista CSAF | Advisory index links to per-advisory CSAF | EOS releases, product relationships and fixes |
| Arista PSIRT page facts | Advisory index links to advisory pages | Explicit introduced EOS release plus vendor-stated configuration condition; no inferred later ranges or absent-device clears |
| Cisco EoX and endoflife.date | Lifecycle milestones with linked publisher evidence | Hardware and software support dates |
| Cisco ASA compatibility matrix | Exact ASA release rows with strict YES/dash platform mapping | Complete platform set only when every publisher table header and marker validates |

Treat hotfix relationships separately from base software releases. A CSAF product ID can refer to a software-and-hotfix combination. Marking its base release fixed would clear systems that still need the hotfix.

See [source rights](DATA_SOURCES.md) for deployment restrictions and [adding an OEM](ADDING_AN_OEM.md) for the package template and acceptance criteria.
