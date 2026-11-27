# OSAK Cloudflare edge runbook

## Route map

| Public path | Edge behavior | Origin requirement |
| --- | --- | --- |
| /, /privacy, /terms, static assets | Workers Assets binding (ASSETS) | none |
| /api/* | Worker proxy | PUBLIC_ORIGIN + X-OSAK-Origin-Secret |
| /docs, /openapi.json | Worker proxy | same |
| /mcp | Worker proxy, streaming body preserved | same |
| /api/v1/admin/* | Cloudflare Access policy + Worker exact service-token check | same, plus internal admin header |

Set PUBLIC_ORIGIN to the already-approved operator-controlled HTTPS origin reached through cloudflared. Do not create an additional public hostname during this readiness pass. The Worker-to-origin secret protects every path even if a tunnel endpoint is discoverable; keep origin details out of the website and public API responses. [Cloudflare Tunnel routing](https://developers.cloudflare.com/tunnel/concepts/routing/)

## Required Worker settings

Set these in the intended Worker environment. Do not commit values to wrangler.toml, .dev.vars, CI logs, or the repository.

| Name | Kind | Purpose |
| --- | --- | --- |
| PUBLIC_ORIGIN | encrypted secret or protected variable | private HTTPS origin URL for the API host/container |
| ORIGIN_SHARED_SECRET | encrypted secret | Worker-to-origin header X-OSAK-Origin-Secret; backend reads the matching host secret as OSAK_ORIGIN_SHARED_SECRET and rejects missing/wrong values |
| ACCESS_SERVICE_TOKEN_ID | encrypted secret | expected signed service-token common name for admin requests |
| ACCESS_TEAM_ISSUER | public setting | Trusted HTTPS Access issuer for admin assertions |
| ACCESS_ADMIN_AUDIENCE | public setting | Audience tag of the OSAK Admin API Access app |
| OSAK_ADMIN_ACCESS_TOKEN | encrypted secret | internal X-OSAK-Admin-Access value injected only after the signed Access assertion check; backend uses the same value |
| TURNSTILE_SITE_KEY | public value | injected by the Worker into the home document at delivery time |
| REPOSITORY_URL | public value | eventual HTTPS repository URL; the link remains hidden when absent or invalid |

Turnstile's secret key belongs only to the backend account/signup service. The browser site key is not a secret, but it is still deployment-specific and intentionally blank in this worktree.

The Worker injects TURNSTILE_SITE_KEY and REPOSITORY_URL into the home document at delivery time. Do not edit the committed meta tag or add an owner-specific repository URL until B2 is confirmed.

## Before first apply

1. Confirm the GitHub repository owner/name and the Worker account ID; this worktree assumes neither.
2. Confirm B1 origin host, tunnel name, and the origin's exact expected shared-secret header behavior.
3. Keep the dedicated proxied origin CNAME. Immediately before binding the Worker Custom Domain in web/wrangler.toml, verify the temporary public CNAME by its record ID, name and target in the ledger. Remove only that OSAK placeholder CNAME. Cloudflare creates the Custom Domain record. A changed target requires reconciliation with its owner. Preserve the zone's wildcard and unrelated records.
4. A Workers Custom Domain issues an Advanced Certificate for the exact hostname, including multi-level names, without a separate ACM subscription. Wait for issuance and verify an HTTPS connection with hostname validation before go-live. [Cloudflare certificate behavior](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#certificates)
5. Create a Cloudflare Access application scoped to /api/v1/admin/*, allow only the approved service token (no user-email bypass), and retain the service-token values in the secret manager.
6. Register the Turnstile site key/secret for the exact hostname and configure the backend to verify tokens server-side.
7. Keep `rate-limits.json` and `waf-rules.json` aligned with the applied rule IDs and expressions above. Future changes must append/update only OSAK-host-scoped rules and must read back the complete ruleset before and after applying. Do not replace the zone ruleset with an example payload. Verify the account plan supports any new fields or characteristics. [Rulesets API procedure](https://developers.cloudflare.com/waf/rate-limiting-rules/create-api/)

## Local verification

From this web/ directory:

~~~sh
cp .dev.vars.example .dev.vars
npm ci
npm run build
npm test
npm run check
npx --yes wrangler@4.168.0 dev --local
~~~

For an origin mock, point PUBLIC_ORIGIN at a local HTTP/HTTPS-capable proxy or backend. Do not point a local Worker at a production origin without explicit approval.

Set `OSAK_TEST_KEY` to a dedicated smoke-test key for this instance and check the public routes.

~~~sh
curl -i https://osak.lab.scogo.ai/api/v1/health
curl -i https://osak.lab.scogo.ai/docs
curl -i https://osak.lab.scogo.ai/openapi.json
OSAK_SMOKE_TEST_KEY="$OSAK_TEST_KEY" uv run python deploy/scripts/smoke_mcp.py
~~~

The smoke script uses a Streamable HTTP client to call all seven MCP tools. The Worker adds `X-OSAK-Origin-Secret` on every origin request and adds `X-OSAK-Admin-Access` only after Cloudflare Access validates an admin request. Check that the origin rejects direct requests that lack the Worker secret. Keep test and live keys out of tickets, logs, and commits.

The Worker sets Cache-Control and CDN-Cache-Control to no-store on every proxied origin response, including API/MCP errors, while returning streaming bodies directly.

## Deployment and rollback

1. Run the static build and Node tests in CI.
2. Run npx --yes wrangler@4.168.0 deploy --dry-run --env production --config web/wrangler.toml with the target account/environment and the approved TURNSTILE_SITE_KEY/REPOSITORY_URL vars; inspect the generated asset list and route bindings.
3. Apply the Worker once production access, certificate coverage and launch approvals are in place. Record the deployment ID and commit SHA.
4. Run production smoke tests for /, /privacy, /terms, /api/v1/health, /docs, /openapi.json, and /mcp with a production smoke-test key. Do not send customer inventory in smoke tests.
5. If smoke tests fail, roll back the Worker to the previous known-good deployment ID with Wrangler. Keep the backend and DNS unchanged unless the incident requires a separately approved rollback.

## Secret rotation

- Rotate ORIGIN_SHARED_SECRET by accepting the new value on the origin first, updating the Worker, checking health/docs/MCP, then retiring the old value.
- Rotate the Access service token in Cloudflare Access and Worker together; test admin denial with the old values and allow with the new values.
- Rotate OSAK_ADMIN_ACCESS_TOKEN on the backend and Worker together; verify that the old internal header is rejected before retiring it.
- Rotate the backend Turnstile secret and Resend/API secrets only through their respective secret stores. Never include them in static assets.

## Incident boundaries

Do not disable the origin shared-secret check, Access policy, ZDR body redaction, or edge limits as a first response. If a source feed is stale, show the source status and investigate the connector; do not fabricate a sync time. If the TLS check fails for this two-level hostname, stop before go-live and obtain certificate coverage.
