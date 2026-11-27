# OSAK quality checks

Run the checkout's test suite with `uv sync --locked` and `uv run pytest`.
The hosted production release gate runs its independent vendor benchmark in
Scogo's private release repository with licensed fixtures.

The deployment workflows require a configured production environment and
the repository variable `OSAK_PRODUCTION_DEPLOY_ENABLED`. Keep deployment
disabled on a source mirror. See the [operations runbook](RUNBOOK.md) for
the production controls.

## ZDR canary

The canary posts a generated asset reference through both `/api/v1/match` and
`/api/v1/resolve`, exercises successful and malformed inputs through the
official Streamable HTTP MCP SDK (`check_assets` and `resolve_inventory`), and
checks the recent metadata-only request audit. Only after all requests finish
does it read the configured database and live log sinks. It never prints the
canary or credentials:

```bash
uv run python scripts/qa/zdr_canary.py \
  --base-url http://127.0.0.1:8000 \
  --api-key "$OSAK_ZDR_API_KEY" \
  --db-url "$OSAK_ZDR_DATABASE_URL" \
  --log-sink-url "$OSAK_ZDR_LOG_SINK_URL" \
  --production
```

Production mode requires a non-local HTTPS API URL, a read-only database URL,
and at least one live Cloudflare/host log-sink URL. It fails closed if any
configured sink, database, usage audit, or binary raw-store scan is unreadable.
It performs no seed, write, rotation, or ingestion operation. Dispatch the Production QA workflow from main. Its protected GitHub environment
provides a live smoke key and the credentials for the restricted Access SSH
connection. The origin runs the test through the public Worker URL and reads the
database and live service logs locally. Configure any additional log sinks on
the origin. The runner only receives the test result.

The normal CI workflow also runs a disposable Postgres 16 + Uvicorn API + live
log-sink process. It migrates and seeds only that job's database, then runs the
same canary against the real REST app and MCP SDK before terminating both
processes.

## Signup and admin smoke

With the local API and Mailpit stack running and a development admin key
available:

```bash
OSAK_COMPOSE_ENV_FILE=/tmp/osak-compose.env \
OSAK_COMPOSE_PROJECT=osak-local \
OSAK_ADMIN_ACCESS=local-admin-token \
uv run python scripts/qa/signup_admin_smoke.py \
  --base-url http://127.0.0.1:8000 \
  --mailpit-url http://127.0.0.1:8025
```

The flow submits the signup form once, receives exactly one Mailpit message
containing the test API key, authenticates `/me`, and checks that a duplicate
signup does not rotate the key or create a second active key. It then creates
and authenticates an admin-issued key, queries usage, and revokes the key.
Tokens and keys are never printed. The Compose options let the script seed its
scoped admin key through the local `osak admin` CLI.

For SA 0087 the affected-device fixture specifies both DHCP relay prerequisites documented in the publisher's configuration section. The original abbreviated feature alone cannot establish the affected state, and the connector regression test exercises that incomplete input. A release-only observation is kept separate from the configuration evidence. When multiple records for the same CVE and product are returned, conflicting definitive verdicts count as unknown. Any explicit clearance of an expected affected case also counts as a false clearance.
