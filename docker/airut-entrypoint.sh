#!/usr/bin/env bash
set -euo pipefail

# Allow Claude to run as root in sandbox (container) environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for mitmproxy network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Sync Python dependencies on container start
if [ -f /workspace/pyproject.toml ]; then
    uv sync --quiet
fi

# Run Claude Code with all arguments passed through
exec claude "$@"
