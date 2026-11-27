# OSAK — Open Security Advisory Kosh

OSAK helps security teams decide which vendor advisories apply to the equipment they maintain. *Kosh* (कोष) means treasury. Submit a vendor, OS and software release to get a deterministic verdict, the evidence for it, and available remediation. The same matcher can run locally with a dataset export.

**Zero Data Retention for asset inventories.** The matching and resolution interfaces process inventory in memory. Account records support key management. Request metadata supports quotas and abuse prevention and has a 90-day retention period before aggregation. See [the retention policy](docs/ZDR.md) and [current verification status](PROGRESS.md).

## Hosted service

Submit the short signup form to receive one email with a working API key. Use the key in the Swagger UI or a Streamable HTTP MCP client. A repeat submission preserves the current active key. [Request a key](https://osak.lab.scogo.ai/#get-key) · [API and MCP quickstart](https://osak.lab.scogo.ai/quickstart) · [Swagger](https://osak.lab.scogo.ai/docs) · [OpenAPI](https://osak.lab.scogo.ai/openapi.json).

The hosted matching dataset focuses on Cisco, Fortinet and Arista.
Use the source status endpoint to check coverage and freshness.

## Local quick start

From the repository root, install Docker with the Compose plugin. The local stack uses PostgreSQL 16 and Mailpit.

```sh
docker compose up --build -d
docker compose exec api osak seed --dev
```

Copy the printed test key into a temporary environment variable. Registered email can be inspected in Mailpit at `http://localhost:8025`. Swagger is at `http://localhost:8000/docs`.

```sh
read -rs OSAK_API_KEY
export OSAK_API_KEY
curl -fsS http://localhost:8000/api/v1/health
curl -fsS -H "X-API-Key: $OSAK_API_KEY" http://localhost:8000/api/v1/me
curl -fsS http://localhost:8000/api/v1/match \
  -H "X-API-Key: $OSAK_API_KEY" -H 'Content-Type: application/json' \
  -d '{"assets":[{"asset_ref":"local-firewall","vendor":"fortinet","os":"FortiOS","version":"7.2.5"}]}'
```

Use the source status endpoint to check which feeds have finished syncing. A newly started database has no advisory evidence. An unknown result requires further review.

## Remote MCP

Follow the [hosted quickstart](https://osak.lab.scogo.ai/quickstart#mcp-title) for Claude Code or Codex setup and test prompts.

For a Streamable HTTP client that supports interactive inputs, use the configuration below and enter your key when prompted. For local use, change the URL to `http://localhost:8000/mcp`.

```json
{
  "inputs": [
    { "type": "promptString", "id": "osakKey", "description": "OSAK API key", "password": true }
  ],
  "servers": {
    "osak": {
      "type": "http",
      "url": "https://osak.lab.scogo.ai/mcp",
      "headers": { "Authorization": "Bearer ${input:osakKey}" }
    }
  }
}
```

The tools are `list_new_advisories`, `get_advisory`, `check_assets`, `resolve_inventory`, `get_fix_options`, `get_eol` and `explain_verdict`. Supply the asset again when asking for an explanation. OSAK does not keep it for a follow-up call.

## Offline matching

Use the authenticated `GET /api/v1/datasets/latest` manifest and its download link. Save the JSONL file locally and verify its SHA-256 digest before evaluating assets. The `osak.match` and `osak.versions` modules run without a web server or database.

With the manifest and its JSONL file saved in the same directory, run the following from that directory.

```python
import json
from pathlib import Path

from osak.core.models import Asset, MatchRequest
from osak.match import load_dataset_jsonl, match_assets

manifest = json.loads(Path("latest.json").read_text())
dataset = load_dataset_jsonl(Path(manifest["dataset_path"]), manifest["sha256"])
asset = Asset(asset_ref="edge-firewall", vendor="fortinet", os="FortiOS", version="7.2.4")
print(match_assets(dataset, MatchRequest(assets=[asset])).model_dump_json(indent=2))
```

## Administer keys

On the local stack, create an account, use the returned user ID to issue a test key, and revoke by key ID. The create command prints the secret once. Set `user_id` and `key_id` to the IDs returned by the preceding commands.

```sh
docker compose exec api osak admin users create --name "Local Operator" --organization "Lab" --email operator@example.com
docker compose exec api osak admin keys create --user-id "$user_id" --environment test
docker compose exec api osak admin usage --user-id "$user_id"
docker compose exec api osak admin keys revoke --key-id "$key_id"
```

At the public edge, send your admin API key and the Cloudflare Access service token together. Create a key with `POST /api/v1/admin/keys` and revoke the returned ID with `DELETE /api/v1/admin/keys/{id}`. To rotate your own key, use `POST /api/v1/keys/rotate` with your current key. See [the operations runbook](docs/RUNBOOK.md) for deployments, backups and recovery.

## Development

Install Python 3.12 and uv. Use `uv sync --locked`, `uv run pytest`, `uv run ruff check` and `uv run mypy src/osak/match src/osak/versions`. See [architecture](docs/ARCHITECTURE.md), [connector development](docs/ADDING_AN_OEM.md) and [operations](docs/RUNBOOK.md).

Scogo.AI maintains OSAK. The code is licensed under [Apache-2.0](LICENSE). Source data has separate [licenses and attribution requirements](docs/DATA_SOURCES.md). This product uses data from the NVD API but is not endorsed or certified by the NVD.
