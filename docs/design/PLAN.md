# Open Advisory Correlation Service — High-Level Plan

> Working name: **advisoryhub** (placeholder, rename freely)
> Owner: Scogo.AI · Status: Draft v0.1 (27 Nov 2026) · Audience: Codex / engineering brainstorming
> Every source below was checked on 25–27 Nov 2026. Items marked **VERIFY** are not confirmed yet. Confirm them before building on them.

---

## 1. Problem and vision

NOC and SOC teams receive OEM security advisories (Cisco, Fortinet, Arista, Palo Alto and others) in different formats, on different schedules, from different portals. Their tools can tell them which CVEs exist. They cannot reliably answer the question that matters:

> **"Is this advisory relevant to the exact devices, models, and versions *we* own, and what should we do?"**

**Vision:** a free, open-source, self-hostable **API service with a built-in remote MCP server**. It:

1. **Aggregates** advisories from many sources (free by default, paid optional) into one normalized, provenance-tracked dataset.
2. **Correlates** a customer's actual assets (vendor, model/PID, OS, version, serial) against that dataset deterministically.
3. **Returns** a verdict per asset: `affected | not_affected | unknown`, plus the reason, fixed versions, workarounds, KEV/EPSS priority, and EoL status.
4. **Is extensible:** the community adds OEMs, categories and sources as plugins, without touching the core.

Scogo will run a free public instance and integrate it into the Scogo AI platform (SIA / Nexus) via MCP. The platform already holds customer inventory: network devices, endpoints, applications, databases.

### Scope roadmap
| Stage | Domain | OEMs / sources |
|---|---|---|
| **v1 (mandatory)** | Network | **Cisco, Fortinet, Arista** |
| v1.x | Network / Security | Palo Alto, Juniper, HPE Aruba, Zscaler |
| v2 | NOC / SOC vendors | CrowdStrike, Check Point, F5, SonicWall, and others |
| v3+ | OS, applications, databases | Via OSV / distro CSAF / vendor feeds |

### Non-goals for v1
- Active scanning of customer networks. Inventory is always provided by the caller.
- Config-level applicability (for example, "is SSL-VPN enabled?"). v1 records feature preconditions so they can be checked later. Config evaluation is v2.
- Blast radius and topology impact. That belongs to the consumer platform (Scogo), not this service.

---

## 2. Prior art (build on it, don't reinvent it)

| Project | What it gives us | License / caveat | How to use it |
|---|---|---|---|
| **CIRCL Vulnerability-Lookup** | Multi-source aggregator with feeders for NVD, CVE List, KEV, CSAF (Cisco, CERT-Bund, NCSC-NL…), EPSS, watchlists, API and pub/sub | **AGPL-3.0** | Use as an optional upstream source and cross-check, or run as a sidecar. Don't fork it into our core unless we accept AGPL for the whole service. |
| **gocsaf/csaf** (BSI) | CSAF downloader, aggregator, checker and validator as a Go library and CLI | Apache-2.0 (older `csaf_distribution` was MIT) | Use for all CSAF fetching and validation. Don't write our own CSAF crawler. |
| **CVEProject/cvelistV5** | Official CVE records, updated ~every 7 min, with hourly delta zips and `deltaLog.json` | CVE Program Terms of Use | Primary CVE backbone (see §4) |
| **Nautobot Device Lifecycle Mgmt app** | Data model: CVE ↔ Software ↔ Device → "Vulnerability" object. It already discovers NIST CVEs for several network OSes, including ArubaOS and PAN-OS | Apache-2.0 (**VERIFY**) | Reference for the domain model and correlation semantics. Possible future integration target. |
| **NbRisk (NetBox plugin)** | Maps platform/device type to CPE, then queries NVD + KEV + EPSS per device | **VERIFY** | Reference for the CPE-mapping approach and its weaknesses (it is NVD-only) |
| **OpenCVE** | CVE monitoring with vendor/product subscriptions and an API | **BSL (source-available, not OSI open source)** | Use only as product and UX reference. Don't build on it. |
| Existing CVE MCP servers (`cve-mcp`, `nist-nvd-mcp-server`, …) | NVD/KEV/EPSS tools for LLMs | Various | Reference for MCP tool design and NVD rate-limit pacing |
| `univers` / purl `vers` spec | Version-range expressions and comparison | **VERIFY** fitness for network OS versions | Candidate base for the version engine (§6.3) |

**Positioning (be honest about it):** Correlation tools already exist: Nautobot DLM, NetBox plugins, ManageEngine NCM firmware vulnerability, IP Fabric, Titania Nipper. They are mostly NVD/CPE-based, tied to one inventory tool, or commercial. Our differentiation:
- OEM-advisory-native, not CPE-only
- Multi-source with per-field provenance
- Inventory-agnostic API + MCP
- Free and open
- Community-extensible connectors

---

## 3. Review of the Grok draft (verified 27 Nov 2026)

| Grok claim | Verdict | Action in this plan |
|---|---|---|
| NVD API 2.0 as the **base layer** | Rate limits are correct: 5 req/30 s without a key, 50 req/30 s with a free key. **Base-layer choice is wrong.** NVD enrichment lags, and a public free service can't depend on that rate limit. | Use **cvelistV5 as the backbone** (CNA-authored affected ranges). Use NVD only for CPE/CVSS enrichment, mirrored locally and synced incrementally. |
| Cisco openVuln API, free registration, version query, fixed versions, CSAF | Correct. Version-based checks only cover Software Checker products: ASA, FMC, FTD, FXOS, IOS, IOS XE, NX-OS. | Keep. Treat other Cisco products as CSAF + CNA records. |
| Palo Alto `/json` + beta API | Correct. `/json` and `/json/{id}` are the more stable endpoints. `/api/v1/products/{p}/{v}/advisories` is beta. Per-advisory CSAF also exists at `/csaf/{id}`. | Prefer `/json`. Use the beta API for version checks, with fallback. |
| Fortinet "CSAF/CVRF per advisory" | **Not verified.** | Use the RSS feed `https://www.fortiguard.com/rss/ir.xml` as the trigger, and Fortinet's CNA records in cvelistV5 for affected versions and solutions. Use the advisory page as an enrichment fallback. Investigate CSAF separately. |
| Juniper "limited, no bulk API" | Partly true | Use RSS `https://supportportal.juniper.net/knowledgerss?type=Security`, Juniper CNA records, and CERT-Bund / NCSC-NL CSAF. |
| Zscaler "fewer product CVEs, more third-party notices" | True for `zscaler.com/security-advisories`, which covers third-party protection notices. | Ingest **`trust.zscaler.com/rss-feed/advisories`** (product advisories). **Exclude** the marketing advisories feed. |
| Vulners pricing (Free 100 credits, Basic $600/mo, Pro $1,300/mo) | Correct | Optional paid connector |
| NotCVE (free, €49+/mo) | Correct. Tiers are free, €49, €199 and €799/mo, and it has MCP access. | Optional paid connector |
| OpenCVE "self-host option" | True, but **BSL-licensed** | Reference only (see §2) |
| CIRCL Vulnerability-Lookup free + self-hostable | Correct (AGPL) | Optional upstream (see §2) |
| "Valters IT Hub" | **Could not verify** | Dropped |
| vuln.today | Exists. Software/dev-focused, plans from $22/mo. | Not relevant for v1 |
| **Missing from Grok:** Arista | Arista publishes **per-advisory CSAF JSON** at `arista.com/assets/data/SecurityAdvisories/CSAF/…` | Add. Arista is a v1 mandatory OEM. |
| **Missing:** cvelistV5, CISA KEV, FIRST EPSS as core feeds; CERT CSAF aggregators; EoL sources | — | Added (§4) |

---

## 4. Data sources

### 4.1 Tiering principle
**Precedence per field:** vendor PSIRT data > vendor CNA record (cvelistV5) > CERT CSAF (CERT-Bund, NCSC-NL) > NVD > third-party aggregators.

Each stored fact keeps `source`, `fetched_at`, `source_url` and `license`. Conflicts are recorded, never silently overwritten.

### 4.2 v1 sources (all free)
| # | Source | Access | Role | Poll |
|---|---|---|---|---|
| 1 | **cvelistV5** (GitHub) | git pull / `cves/deltaLog.json` / hourly delta zip | CVE backbone. CNA-authored affected versions and solutions. Fortinet and Juniper records verified; Cisco, Arista and PAN CNA status **VERIFY**. | 5–10 min |
| 2 | **CISA KEV** | JSON feed | Exploited-in-the-wild flag | 1 h |
| 3 | **FIRST EPSS** | `api.first.org/data/v1/epss` | Exploit probability | daily |
| 4 | **NVD API 2.0** | REST + free API key | CPE + CVSS enrichment only | incremental by `lastModStartDate` |
| 5 | **Cisco openVuln API v2** | `apix.cisco.com/security/advisories/v2/…` (OAuth, free) | Advisories by OS + version, first fixed release, SMU | 15 min + on-demand |
| 6 | **Cisco CSAF** | `cisco.com/.well-known/csaf/provider-metadata.json` via gocsaf | Full advisory documents, product tree | 15 min |
| 7 | **Fortinet PSIRT RSS** | `fortiguard.com/rss/ir.xml` | New-advisory trigger. Monthly cycle (2nd Tuesday) plus out-of-cycle criticals. | 15 min |
| 8 | **Fortinet advisory pages** | `fortiguard.fortinet.com/psirt/FG-IR-…` | Enrichment fallback when the CNA record is incomplete (parsing; respect ToS) | on trigger |
| 9 | **Arista CSAF** | per-advisory JSON; discovered by crawling the advisory index (no confirmed feed or provider-metadata, **VERIFY**) | Affected/fixed versions | 30 min |
| 10 | **CERT-Bund WID CSAF / NCSC-NL CSAF** | CSAF via gocsaf | Cross-vendor fallback and cross-check | 1 h |

### 4.3 v1.x / v2 sources
| Vendor | Source |
|---|---|
| Palo Alto | `security.paloaltonetworks.com/json`, `/json/{id}`, `/api/v1/products/{p}/{v}/advisories` (beta), `/csaf/{id}`. Monthly (2nd Wednesday). |
| Juniper | RSS `supportportal.juniper.net/knowledgerss?type=Security`; quarterly (2nd Wednesday of Jan/Apr/Jul/Oct) + out-of-cycle; CNA records; CERT CSAF |
| HPE Aruba | CSAF at `csaf.arubanetworking.hpe.com` |
| Zscaler | `trust.zscaler.com/rss-feed/advisories` |
| F5 | MyF5 custom RSS (see F5 K9957) |
| SonicWall | `psirtapi.global.sonicwall.com` (**VERIFY** schema) |
| Check Point | No RSS. Scrape `support.checkpoint.com/security-advisories` (ToS check). |
| CrowdStrike | **Not researched yet** |
| Optional upstream | CIRCL Vulnerability-Lookup API (cross-check and gap fill) |

### 4.4 EoL / lifecycle sources
| Source | Notes |
|---|---|
| Cisco EoX API v5 | Lookup by product ID, serial number, or software release string. Needs Cisco API access (**VERIFY** entitlement). |
| endoflife.date | FortiOS JSON at `/api/v1/products/fortios/`. API is beta. Check coverage for PAN-OS, IOS XE, EOS. |
| eol.network | Free community API (token), with a bulk `/match` endpoint for Cisco/Juniper part numbers |

### 4.5 Optional paid connectors (disabled by default)
All use the same connector interface (§6.1) and are enabled by config plus API key. They are never required for core function.

| Provider | Pricing (verified) | Value |
|---|---|---|
| Vulners | Free 100 credits/mo; Basic $600/mo (600 credits); Pro $1,300/mo (3,000 credits); `search/id` is credit-free | Vendor bulletin aggregation, exploits, MCP |
| NotCVE | Free; €49 / €199 / €799 per month | CVEs + non-CVE issues, CPEs, MCP |
| VulDB | Credit-based | Broad coverage |
| VulnCheck | Annual contract (AWS Marketplace) | Exploit intelligence, enhanced KEV |
| Flashpoint VulnDB | Contract, no public price | Non-CVE vulnerabilities, affected/unaffected versions |

### 4.6 Data licensing (must resolve before the public launch)
- Review terms of use for **each** source: Cisco API terms, FortiGuard, Arista, PAN, CERT-Bund, NVD, CVE Program, EPSS, KEV.
- Default posture: store **structured facts** (IDs, versions, scores, dates) plus a **link** to the vendor advisory. Don't republish full vendor advisory text.
- Expose each source's license and attribution in API responses (`provenance[]`).
- Paid-connector data is **never** redistributed through the public instance. It is only usable on self-hosted instances under the operator's own license.

---

## 5. Architecture

```
                ┌──────────────────────── Connectors (plugins) ────────────────────────┐
                │ cvelistv5 │ kev │ epss │ nvd │ cisco_openvuln │ csaf(gocsaf) │ rss │ … │ paid_* │
                └───────┬──────────────────────────────────────────────────────────────┘
                        │ raw docs (immutable, content-hashed)
                        ▼
  Scheduler ──► Ingestion workers ──► Raw store (object storage / FS)
                        │
                        ▼
                  Normalizer (per-connector mapper → canonical model)
                        │
                        ▼
                  Merger (precedence rules + provenance + conflict log)
                        │
                        ▼
            PostgreSQL (canonical advisories, products, version ranges, EoL)
                        │
        ┌───────────────┼──────────────────────┬──────────────────────┐
        ▼               ▼                      ▼                      ▼
   REST API (v1)   Remote MCP server      Event stream          Dataset export
   /advisories     (Streamable HTTP,      (webhooks / SSE:      (nightly JSONL /
   /match          same core functions)   new/updated           Parquet for
   /products                              advisories)           offline matching)
   /eol
```

**Key principles**
- **One core, two faces.** REST and MCP call the same service layer. MCP tools are thin wrappers.
- **Deterministic matching.** Version comparison and range evaluation are code, never an LLM. LLMs may assist **extraction** (for example, parsing feature preconditions from advisory text) only behind a review flag.
- **Inventory privacy.** Support three modes: (a) call `/match` on the public instance with no inventory retention, (b) self-host, (c) download the dataset export and match locally with the same open-source matching library. Mode (c) is how Scogo can keep customer inventory inside its own platform.
- **Idempotent, replayable ingestion.** Raw documents are content-hashed, so a re-normalize is possible at any time.

**Suggested stack (Codex to confirm)**
- Python 3.12: FastAPI (REST) + official MCP Python SDK / FastMCP (remote MCP over Streamable HTTP) + Pydantic models
- PostgreSQL 16 (JSONB for raw normalized payloads)
- Worker queue (Postgres-based such as `procrastinate`, or Redis + RQ/Celery)
- gocsaf CLI invoked as a subprocess, or a small Go sidecar, for CSAF
- Packaging: Docker Compose for local and self-host, Helm chart for Kubernetes (fits the existing AKS / DOKS setup)
- Matching core as a **standalone library** (`advisoryhub-match`) usable without the server

---

## 6. Core design

### 6.1 Connector plugin contract
Every source, free or paid, implements:

```python
class Connector(Protocol):
    id: str                     # "fortinet_psirt_rss"
    vendor_scope: list[str]     # ["fortinet"] or ["*"]
    kind: Literal["advisory", "enrichment", "eol"]
    tier: Literal["free", "paid"]
    license: SourceLicense      # redistribution rules, attribution text
    auth: AuthSpec | None       # none | api_key | oauth_client_credentials
    rate_limit: RateLimit
    schedule: Schedule          # poll interval or cron

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]: ...
    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]: ...
    def healthcheck(self) -> HealthStatus: ...
```

- Connectors are discovered via Python entry points, so a community package can add one without changing the core.
- Each connector ships **fixtures** (recorded raw docs) and **golden normalized outputs** for CI.
- Adding a new OEM = connector + version scheme (§6.3) + product catalog entries (§6.2) + golden tests.

### 6.2 Canonical data model (first cut)
- **Vendor**: `id`, names/aliases, PSIRT URLs, CNA short name
- **Product**: `vendor_id`, family (for example "FortiGate"), OS (for example "FortiOS"), aliases, CPE prefixes, CSAF product-tree IDs, vendor product names
- **HardwareModel**: `vendor_id`, model / PID / SKU, family, EoL milestones
- **Advisory**: `vendor_advisory_id` (`cisco-sa-…`, `FG-IR-…`, `Arista SA 0162`), title, published/updated dates, severity (vendor), CVSS (versioned, by source), CVE IDs, URLs, `status` (interim/final), revision history
- **AffectedRange**: `advisory_id`, `product_id`, optional `hardware_model` filter, version range expression (`vers`-style), `status` (`affected | not_affected | fixed | under_investigation`), `fixed_versions[]`, `first_fixed` per train
- **Condition** (precondition): feature or config prerequisite (for example "SSL-VPN enabled", "S-BFD configured"), extraction method (`vendor_structured | parsed | llm_extracted`), `review_state`
- **Remediation**: upgrade target(s), workaround text/link, SMU/hotfix IDs
- **Enrichment**: KEV (date added, ransomware use), EPSS (score, percentile, date)
- **Provenance**: per-field `source`, `fetched_at`, `url`, `license`, `confidence`
- **EoLRecord**: product/model/version → EoS, end of software maintenance, end of vulnerability support, LDoS

### 6.3 Version engine (the hardest part, so build it first)
Per-OS **version scheme plugins**: parse, normalize, compare, train-aware ranges.

| Scheme | Examples | Notes |
|---|---|---|
| `cisco_ios` | `15.2(7)E4`, `15.6(2)T` | Trains; not linear |
| `cisco_iosxe` | `17.9.4a`, `17.3.5b` | Letter suffixes |
| `cisco_nxos`, `cisco_asa` | `9.3(10)`, `9.18.3` | |
| `fortios` | `7.2.8`, `7.4.4` (+ build `b2573`) | Branch-based fixed versions |
| `arista_eos` | `4.30.1F`, `4.31.0F-1` | Train letters (F/M) |
| `panos` | `11.1.2-h3` | Hotfix suffix |
| `junos` | `21.4R3-S9`, `-EVO` | R/S releases, EVO variant |
| `aos_cx` | `10.13.1000` | |

Requirements:
- Range evaluation must be **train-aware**. "Fixed in 7.2.8" is not the same as "fixed in all > 7.2.8".
- Unknown or unparseable version → `unknown`, never `not_affected`.
- Property-based tests plus vendor-published examples as golden tests.

### 6.4 Correlation / matching
Input (one or many assets):
```json
{
  "assets": [
    {
      "asset_ref": "FW-MUM-DC-01",
      "vendor": "fortinet",
      "product": "fortigate",
      "model": "FG-100F",
      "os": "fortios",
      "version": "7.2.5",
      "serial": "FG100FTK2xxxxx",
      "features": ["ssl_vpn"]
    }
  ],
  "filters": {"min_severity": "high", "kev_only": false}
}
```
Output per asset × advisory:
- `verdict`: `affected | not_affected | unknown`
- `confidence`: `high | medium | low`, plus `reasons[]` (which range matched, from which source)
- `conditions[]`: preconditions and whether they were satisfied, unsatisfied, or unknown (from `features` if provided)
- `fixed_versions[]` / `recommended_target`, plus `workaround`
- `priority` (KEV, EPSS, CVSS, vendor severity), plus `eol` status of the model and version
- `provenance[]`

**Serial numbers:** advisories don't reference serials. A serial is used to resolve model/PID (for example via Cisco EoX by serial) and hardware EoL. The verdict itself is driven by product + model + version (+ features).

**Identity resolution:** map free-text inventory (`"Cisco IOS XE Software, Version 17.3.3a"`) to canonical `product` + `version` via an alias table and parsers. Return `unresolved` assets explicitly.

### 6.5 Public API (v1, sketch)
```
GET  /v1/vendors
GET  /v1/products?vendor=
GET  /v1/advisories?vendor=&product=&since=&severity=&kev=
GET  /v1/advisories/{id}
GET  /v1/cves/{cve_id}
POST /v1/match                     # bulk asset correlation
POST /v1/resolve                   # normalize raw inventory strings → canonical ids
GET  /v1/eol?vendor=&model=&os=&version=
GET  /v1/changes?since=            # incremental feed for consumers
POST /v1/subscriptions             # webhooks for vendor/product (optional v1.x)
GET  /v1/datasets/latest           # export manifest (JSONL/Parquet)
GET  /v1/sources                   # connector health, last sync, license
```
- OpenAPI spec generated and published
- Free API keys for the public instance (rate limiting, abuse control); anonymous low-rate access for read endpoints

### 6.6 Remote MCP server
Served by the same app (for example `/mcp`, Streamable HTTP), with API-key auth.

| Tool | Maps to |
|---|---|
| `list_new_advisories(since, vendors[], min_severity)` | `/advisories`, `/changes` |
| `get_advisory(id)` | `/advisories/{id}` |
| `check_assets(assets[])` | `/match` |
| `resolve_inventory(raw_strings[])` | `/resolve` |
| `get_fix_options(vendor, product, version, advisory_id?)` | match + remediation |
| `get_eol(vendor, model?, os?, version?)` | `/eol` |
| `explain_verdict(asset_ref, advisory_id)` | match reasons + provenance |

Tool outputs must be compact and structured, with links. Never dump raw CSAF into the LLM context.

---

## 7. Phased plan

### Phase 0 — Foundations (≈2 weeks)
- Repo, license decision (recommend **Apache-2.0** for core + matching lib), CONTRIBUTING, CODE_OF_CONDUCT, SECURITY.md
- Canonical schema + migrations; connector SDK + entry-point discovery; raw store; scheduler
- Connectors: **cvelistV5, KEV, EPSS** (backbone)
- Version engine skeleton + `fortios`, `cisco_iosxe`, `arista_eos` schemes with golden tests

### Phase 1 — Mandatory OEMs + matching (≈4–6 weeks)
- **Cisco**: openVuln API (OAuth) + CSAF (gocsaf); `cisco_ios`, `cisco_nxos`, `cisco_asa` schemes
- **Fortinet**: RSS trigger + CNA records + advisory-page enrichment fallback
- **Arista**: CSAF crawler + `arista_eos` ranges
- Merger + provenance + conflict log
- `/match`, `/resolve`, `/advisories`, `/eol` (Cisco EoX, endoflife.date FortiOS)
- Remote MCP server with the tool set from §6.6
- **Accuracy gate** (§8) before anything goes to a customer

### Phase 2 — Scogo integration + public beta (≈3–4 weeks)
- Scogo platform: inventory sync → `/resolve` → `/match`. Findings surface in SIA / Nexus; ticket and CR creation stays in Scogo.
- Local-match mode using the dataset export (customer inventory never leaves Scogo)
- Public free instance: API keys, rate limits, status page, docs site
- Webhooks / `changes` feed

### Phase 3 — Expand network/security OEMs (ongoing)
- Palo Alto, Juniper, HPE Aruba, Zscaler, then F5, SonicWall, Check Point; research CrowdStrike
- CERT-Bund / NCSC-NL CSAF fallback connectors; optional CIRCL upstream connector
- Optional paid connectors (Vulners, NotCVE) behind config flags

### Phase 4 — Applicability and new domains
- Condition evaluation from device config / feature flags (structured `features` input, then config parsers)
- OS / applications / databases (OSV, distro CSAF, vendor feeds) using the same connector contract

---

## 8. Quality and accuracy (non-negotiable before customer use)
- **Golden dataset:** 50–100 real device/version combos across Cisco IOS XE, NX-OS, ASA, FortiOS and Arista EOS. Expected results come from the vendor's own tools: Cisco Software Checker / openVuln, Fortinet advisory tables, Arista advisories.
- **Target:** ≥98% verdict agreement on mandatory OEMs. **Zero `not_affected` where the vendor says affected.** False negatives are the critical failure.
- **Source drift monitors:** schema/format change detection per connector, failing-sync alerts, and stale-data flags in API responses.
- **Contract tests** for each connector, using recorded fixtures.
- **Cross-source diff report:** vendor vs CNA vs NVD vs CERT disagreements, surfaced for maintainers.

## 9. Open-source and community model
- Monorepo: `core/`, `match-lib/`, `connectors/<vendor>/`, `schemes/<os>/`, `mcp/`, `deploy/`
- "Add an OEM" guide + cookiecutter template (connector + scheme + fixtures + golden tests)
- Maintainer review required for new connectors; per-connector CODEOWNERS
- Public dashboard of source health and coverage per vendor

## 10. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Vendor feed format changes, or scraping breaks | Prefer CSAF / APIs; drift monitors; graceful `unknown` |
| Source ToS forbid redistribution | §4.6 licensing review; facts + links only; per-source flags |
| Wrong "not affected" verdict → customer breach | Conservative defaults (`unknown`), confidence + provenance, golden tests, accuracy gate |
| NVD lag and rate limits | cvelistV5 backbone; local NVD mirror only for enrichment |
| Public instance abuse / cost | API keys, rate limits, caching, dataset export to offload heavy users |
| Inventory sensitivity | No-retention `/match`; self-host; local-match library |
| AGPL contamination | Treat CIRCL as an external service / optional connector, not vendored code |

## 11. Open questions for brainstorming
1. Final name and license (Apache-2.0 vs MPL-2.0 vs AGPL for the server only)?
2. Python end-to-end, or a TypeScript API (matching the NestJS stack) + Python workers?
3. Use `univers`/`vers` for ranges, or our own range model?
4. Product identity: CPE-first, CSAF product-tree-first, or our own IDs with mappings to both?
5. Does the public instance accept bulk `/match` from anonymous users, or only with a key?
6. Who reviews LLM-extracted conditions, and what is the SLA?
7. Cisco EoX / openVuln API terms: can derived data be served on a public instance?
8. Governance: Scogo-owned GitHub org vs a neutral foundation later?

## 12. Definition of done (v1)
- Cisco, Fortinet and Arista advisories ingested automatically within ≤30 min of vendor publication (RSS/CSAF/CNA)
- `/match` and the MCP `check_assets` pass the golden dataset gate
- Docker Compose one-command self-host; public instance live with docs
- Scogo SIA can answer: "Which of my devices are affected by today's advisories, and what's the fix?" using live inventory
