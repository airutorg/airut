# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container entrypoint generation.

Generates the entrypoint script in code rather than reading from an
external file. The entrypoint is fundamental to sandbox operation
(IS_SANDBOX, CA trust).

Two variants:

- **Agent entrypoint**: Runs Claude Code (``exec claude "$@"``).
  Used by AgentTask for sandboxed Claude execution.
- **Passthrough entrypoint**: Runs any command (``exec "$@"``).
  Used by CommandTask for arbitrary command execution.
"""

from __future__ import annotations


# The agent entrypoint script content. Changes to this string will
# change the overlay image hash, triggering a rebuild.
AGENT_ENTRYPOINT_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail

# Allow Claude to run as root in sandbox environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Run Claude Code with all arguments passed through
exec claude "$@"
"""

# The passthrough entrypoint script content. Runs any command
# passed as arguments instead of hardcoding claude.
PASSTHROUGH_ENTRYPOINT_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail

# Mark as sandbox environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Run the command passed as arguments
exec "$@"
"""


def get_entrypoint_content(*, passthrough: bool = False) -> bytes:
    """Get the entrypoint script content as bytes.

    Args:
        passthrough: When True, return the passthrough entrypoint
            (``exec "$@"``).  When False (default), return the agent
            entrypoint (``exec claude "$@"``).

    Returns:
        UTF-8 encoded entrypoint script.
    """
    script = (
        PASSTHROUGH_ENTRYPOINT_SCRIPT
        if passthrough
        else AGENT_ENTRYPOINT_SCRIPT
    )
    return script.encode("utf-8")
