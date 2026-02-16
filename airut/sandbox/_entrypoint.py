# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container entrypoint generation.

Generates the entrypoint script in code rather than reading from an
external file. The entrypoint is fundamental to sandbox operation
(IS_SANDBOX, CA trust).
"""

from __future__ import annotations


# The entrypoint script content. Changes to this string will
# change the overlay image hash, triggering a rebuild.
ENTRYPOINT_SCRIPT = """\
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


def get_entrypoint_content() -> bytes:
    """Get the entrypoint script content as bytes.

    Returns:
        UTF-8 encoded entrypoint script.
    """
    return ENTRYPOINT_SCRIPT.encode("utf-8")
