#!/usr/bin/env bash
set -euo pipefail

# Allow Claude to run as root in sandbox (container) environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for mitmproxy network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Install global-agent for Node.js proxy support when network sandbox is active.
# Node's built-in HTTP client ignores HTTP_PROXY/HTTPS_PROXY, so global-agent
# patches it at startup via NODE_OPTIONS="--require global-agent/bootstrap".
if [ -n "${GLOBAL_AGENT_HTTP_PROXY:-}" ] && command -v npm >/dev/null 2>&1; then
    npm install -g global-agent >/dev/null 2>&1 || true
fi

# Sync Python dependencies on container start
if [ -f /workspace/pyproject.toml ]; then
    uv sync --quiet
fi

# Run Claude Code with all arguments passed through
exec claude "$@"
