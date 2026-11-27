# Asset privacy and retention

The Zero Data Retention promise applies to asset inventories submitted to OSAK. It covers asset references, inventory strings, vendors, models, versions, serials and feature lists in REST requests and MCP tool arguments. A match response returns the caller's asset reference for correlation. A later request cannot retrieve a past inventory.

| Data | Purpose | Retention policy |
|---|---|---|
| Inventory inputs and verdict responses | Resolve and check the current request | Request memory only. Exclude bodies, tool arguments, results and validation inputs from logs, DB tables, traces, caches, error reporting and files. |
| Name, organization, email, key-delivery timestamp, plan, terms version, status and signup IP digest or truncated network | Identify the account, manage access and deliver the one-time API key | Account lifecycle. Public signup leaves `email_verified=false`; receiving a key email is not treated as proof of email ownership. The detailed request log has its own 90-day limit. |
| Key prefix and server-peppered HMAC | Authenticate and revoke credentials | Key lifecycle. Plaintext is shown once or sent in the issuance email. The email provider and recipient handle that message. |
| Request ID, account/key IDs, time, method, route template, allow-listed query filters, status, latency, response size, asset count, MCP tool name, user agent and a masked client IP | Quotas, operations and abuse prevention | 90 days, then roll up to daily counts per user and endpoint. |
| Advisory source documents, normalized facts, conflicts and exports | Reproducible advisory processing | Independent of customer inventories. Source retention and redistribution follow publisher terms. |

The existing `signup_tokens` schema is retained for the previous rollback image.
The single-submit signup path never writes or reads it. Drop the table only
after the rollback image has also adopted single-submit signup.

## Edge and host configuration

Disable request-body capture and sampling on the Worker, WAF, tunnel, API, MCP SDK, reverse proxies and error-reporting services. Keep authorization headers, cookies, legacy verification tokens and raw query strings out of access logs. Serve match, resolve, signup, key and MCP responses with cache bypass. The origin must reject requests that bypass the trusted edge in production.

Back up the database on the documented schedule. The restore procedure must apply expired usage retention before a restored database serves requests. Account or quota metadata in backups is still personal data. Operators who add a proxy, collector or log shipping service must verify its configuration as part of deployment.

## Verification

Use a fresh synthetic canary in successful and invalid REST and MCP requests. Check the response and verify the intended handler ran, then search retained database values, service logs and all configured sinks for the canary. A search of the usage table alone cannot establish the deployment-wide promise. The production acceptance result is tracked in [PROGRESS.md](../PROGRESS.md).
