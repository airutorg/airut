# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container entrypoint generation.

Generates the entrypoint script in code rather than reading from an
external file. The entrypoint is fundamental to sandbox operation
(IS_SANDBOX, CA trust).

Two entrypoint variants are provided:

- **Agent entrypoint** (default): Runs ``exec claude "$@"`` -- used by
  ``AgentTask`` for Claude Code execution.
- **Passthrough entrypoint**: Runs ``exec "$@"`` -- used by
  ``CommandTask`` for arbitrary command execution.
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

# The passthrough entrypoint script content. Same setup as the agent
# entrypoint but runs the command directly instead of Claude.
PASSTHROUGH_ENTRYPOINT_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail

# Allow commands to run as root in sandbox environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Run command with all arguments passed through
exec "$@"
"""


def get_entrypoint_content(*, passthrough: bool = False) -> bytes:
    """Get the entrypoint script content as bytes.

    Args:
        passthrough: If True, return the passthrough entrypoint that
            runs ``exec "$@"`` instead of ``exec claude "$@"``.

    Returns:
        UTF-8 encoded entrypoint script.
    """
    script = (
        PASSTHROUGH_ENTRYPOINT_SCRIPT
        if passthrough
        else AGENT_ENTRYPOINT_SCRIPT
    )
    return script.encode("utf-8")
