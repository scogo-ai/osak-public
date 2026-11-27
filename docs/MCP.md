# OSAK MCP

OSAK exposes the official MCP Python SDK's stateless Streamable HTTP transport
at `/mcp`. Every tool uses the same API key, quota checker, and metadata-only
usage logger as the REST API. `check_assets` and `resolve_inventory` keep
submitted inventory in request memory only.

## Client configuration

For an MCP client that supports a remote HTTP server:

```json
{
  "mcpServers": {
    "osak": {
      "type": "http",
      "url": "https://osak.lab.scogo.ai/mcp",
      "headers": {
        "Authorization": "Bearer osak_live_REPLACE_ME"
      }
    }
  }
}
```

The equivalent header is `X-API-Key: osak_live_REPLACE_ME`. Never put a
plaintext production key in source control or a shared prompt.

## API integration seam

The REST application mounts MCP after its API routes:

```python
from osak.mcp.integration import mount_accounts_mcp

mount_accounts_mcp(app)
```

`accounts_gateway` implements `MCPAccountGateway`: `authenticate_api_key(token)`
returns an `MCPPrincipal` or `None`; `check_mcp_quota(principal, request_id=...,
mcp_tool=..., asset_count=..., user_agent=..., client_ip=...)` atomically
reserves the account usage row and returns `QuotaDecision`; and
`record_mcp_usage(metadata)` finalizes that same row exactly once. The concrete
`AccountsMCPGateway` uses `authenticate_key`, `reserve_usage`, `finalize_usage`,
and `hash_ip` from the accounts service. It never receives tool arguments or
request bodies.

`APIServiceAdapter` binds the seven methods to `osak.api.service`; it receives
the corresponding typed request model. Results are converted to JSON facts and
source links; raw CSAF fields are omitted.
