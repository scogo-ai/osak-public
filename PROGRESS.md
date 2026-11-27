# OSAK release verification

The hosted REST API and Streamable HTTP MCP server support security advisory
lookup and deterministic matching for Cisco, Fortinet and Arista. The
[API and MCP quickstart](https://osak.lab.scogo.ai/quickstart) walks through
signup and manual tests. [Live source status](https://osak.lab.scogo.ai/api/v1/sources)
shows the enabled sources and their latest checkpoints.

The production release passed the 94-case independent publisher benchmark
with no false clearances. Live coverage depends on the source allowlist and
the evidence available for a product. See the [source register](docs/DATA_SOURCES.md).

See the [operations runbook](docs/RUNBOOK.md) and [quality checks](docs/QA.md)
for self-hosted deployment and testing.
