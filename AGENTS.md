# OSAK engineering

Read docs/design/PLAN.md and the source responsibilities in docs/DATA_SOURCES.md. Use Python 3.12 and uv. Run uv sync --locked, uv run pytest, uv run ruff check and uv run mypy src/osak/{match,versions}. See README for local services.

Preserve configured Git authorship. No AI attribution in commits or PR bodies. Choose the simplest current implementation and established libraries. No backward compatibility requirement. Invoke the graphify skill when requested with /graphify.

Keep inventory in request memory only. The library and its dataset have no network or database dependency. Return unknown whenever applicability lacks supporting evidence. Never collect exploit payloads, active discovery results or customer assets in the advisory store. Keep source attribution with facts.
