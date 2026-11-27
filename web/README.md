# OSAK web and edge

This directory is the self-contained public website and Cloudflare Worker router. It has no runtime dependency on the Python package.

## Build and test

~~~sh
npm ci
npm run check
npm test
npm run build
npx --yes wrangler@4.168.0 deploy --dry-run --env production --config wrangler.toml \
  --var TURNSTILE_SITE_KEY:REPLACE_WITH_APPROVED_SITE_KEY
~~~

Run the build before Wrangler. It copies the site into dist/, the directory bound to ASSETS in both environments.

## Runtime contract

The Worker export in src/index.js serves assets and proxies the following same-host routes:

- static: /, /privacy, /terms, and other assets;
- API: /api/*;
- FastAPI docs: /docs and /docs/*;
- OpenAPI: /openapi.json;
- MCP: /mcp and /mcp/*.

The origin is never selected from a request. Set PUBLIC_ORIGIN to the private origin URL reached through the Cloudflare Tunnel. The Worker adds X-OSAK-Origin-Secret from ORIGIN_SHARED_SECRET; the backend must reject a missing or incorrect value using OSAK_ORIGIN_SHARED_SECRET. Admin paths (/api/v1/admin/*) additionally require a signed Access application token with the configured issuer, audience and service-token identity. After that check, the Worker injects X-OSAK-Admin-Access from OSAK_ADMIN_ACCESS_TOKEN and removes client Access headers before proxying. Responses are returned directly so Streamable HTTP bodies are not buffered.

Signup sends one API-key email after the Turnstile and terms checks. There is no verification-link step in this flow. Repeated requests remain generic; an existing active key is never revoked or replaced by a second key.

For local Docker Compose, the backend normally listens on http://127.0.0.1:8000 and the local .dev.vars can point PUBLIC_ORIGIN there. Production should use the private tunnel URL and a non-empty shared secret. The backend Compose environment must map the same secret to OSAK_ORIGIN_SHARED_SECRET; coordinate it through the host secret store, not source control.

## Public beta

The Worker is deployed as `osak-web-production` with a Custom Domain on `osak.lab.scogo.ai`. Its encrypted origin binding, paired Turnstile widget, exact-host certificate, and scoped edge rules are live. The public legal drafts are available at [Privacy](https://osak.lab.scogo.ai/privacy) and [Terms](https://osak.lab.scogo.ai/terms). The admin paths require the dedicated Access service token and an OSAK admin key. See the [resource ledger](../deploy/cloudflare/RUNBOOK.md) and [release gates](../PROGRESS.md).

Build the assets before a production release. The GitHub workflow uses the pinned Wrangler version, production environment secrets and `--keep-vars` for the existing bindings.
