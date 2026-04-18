#!/usr/bin/env bash
# Launch the MCP server on stdio. Intended as the command target for
# Claude Code's `mcpServers` config.
set -euo pipefail
cd "$(dirname "$0")/.."
exec ./.venv/bin/python -m symex_mcp.server
