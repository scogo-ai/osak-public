# Architecture

OSAK has two distinct data paths. A worker reads advisory and lifecycle data from publisher endpoints and writes normalized records to PostgreSQL. A client submits its own inventory to the API or MCP, where the application resolves product identity and evaluates versions against the stored facts in memory.

## Publication

Connector entry points supply source identity, license, rate-limit policy, polling interval and authentication requirements. Each successful fetch returns bytes with a source URL and retrieval time. Store the original bytes by hash before normalization so a changed parser can replay the observation. Use the publisher's product IDs and aliases when assigning canonical IDs.

Preserve source identity per field. Prefer a PSIRT fact over the vendor CNA, then CERT, NVD and aggregators. Record disagreements for review. An enrichment joins on a CVE ID. A KEV flag or EPSS score changes prioritization only. The CVE ID alone does not identify a product or an affected release.

Nightly exports contain the canonical facts, provenance and a checksum. Keep raw publisher documents and private account tables outside the export. Public publication also depends on the source's redistribution rights.

## Applicability

Resolve the caller's vendor, model, product and OS against the catalog. A supported version scheme determines comparable releases within a train. Evaluate applicable ranges, model restrictions and feature prerequisites. Recommend a fixed target only where the relevant evidence identifies one. Retain uncertainty in the response if the identity, version, source or applicability evidence is incomplete.

A serial number can help identify hardware and lifecycle information. It does not change whether the software falls in an affected range. A follow-up MCP explanation requires asset details again.

## Service boundary

PostgreSQL holds accounts, keyed digests, quota state, request metadata and the advisory dataset. FastAPI and the MCP transport share account and matching services. An offline consumer reads a checksummed export and invokes the matcher directly.

A Cloudflare Worker serves static assets and forwards API, OpenAPI, Swagger and MCP requests through the tunnel to the origin. Admin routes require both an admin account key and Cloudflare Access. The production Compose project should publish no host ports. See the [Cloudflare runbook](../deploy/cloudflare/RUNBOOK.md) for edge setup and [PROGRESS.md](../PROGRESS.md) for deployment and verification status.
