# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container entrypoint generation.

Generates the entrypoint script in code rather than reading from an
external file. The entrypoint is fundamental to sandbox operation
(IS_SANDBOX, CA trust).

Two entrypoint variants are provided:

- **Agent entrypoint** (default): Runs ``exec /opt/claude/claude "$@"``
  -- used by ``AgentTask`` for Claude Code execution.  The binary is
  bind-mounted from the host cache at runtime.
- **Passthrough entrypoint**: Runs ``exec "$@"`` -- used by
  ``CommandTask`` for arbitrary command execution.

Both variants share the same setup.  When ``AIRUT_VERBOSE=1`` is set in
the container environment, setup steps log to stderr.  Otherwise setup
is completely silent -- only the sandboxed command's own stdout and
stderr are emitted.
"""

from __future__ import annotations

from airut.sandbox._network import CA_CONTAINER_PATH
from airut.sandbox.claude_binary import CLAUDE_BINARY_CONTAINER_PATH


#: System CA bundle the entrypoint extends with the proxy CA when the
#: image has no ``update-ca-certificates`` (e.g. Nix-based images).
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

# Setup shared by both entrypoint variants.  Changes to the generated
# scripts change the overlay image hash, triggering a rebuild.
_SETUP = (
    f"""\
#!/usr/bin/env bash
set -euo pipefail

airut_ca='{CA_CONTAINER_PATH}'
airut_bundle='{SYSTEM_CA_BUNDLE}'
"""
    + r"""
# Allow running as root in sandbox environment
export IS_SANDBOX=1

# Run a setup step.  Its output goes to stderr when AIRUT_VERBOSE=1 and
# is discarded otherwise, so the sandboxed command's stdout stays clean.
# Stdin is closed so a setup step can never consume the command's input.
airut_setup() {
    if [ "${AIRUT_VERBOSE:-}" = "1" ]; then
        "$@" </dev/null >&2
    else
        "$@" </dev/null >/dev/null 2>&1
    fi
}

# Add the proxy CA to the system bundle without update-ca-certificates.
# The new bundle is renamed over the old path, so a bundle that is a
# symlink (e.g. into /nix/store) is replaced rather than written through.
airut_add_ca_to_bundle() {
    mkdir -p "${airut_bundle%/*}" || return
    { cat "$airut_bundle" 2>/dev/null; echo; cat "$airut_ca"; } \
        >"$airut_bundle.airut-tmp" || return
    mv -f "$airut_bundle.airut-tmp" "$airut_bundle" || return
    echo "Added proxy CA to $airut_bundle"
}

# Trust mounted CA certificate (for network proxy).  The CA environment
# variables set by Airut cover most TLS stacks; the system bundle covers
# tools that only read the default location.
if [ -f "$airut_ca" ]; then
    if command -v update-ca-certificates >/dev/null 2>&1; then
        airut_setup update-ca-certificates || true
    else
        airut_setup airut_add_ca_to_bundle || true
    fi
fi
"""
)

# The agent entrypoint script content.
AGENT_ENTRYPOINT_SCRIPT = (
    _SETUP
    + f"""
# Run Claude Code with all arguments passed through.
# The binary is bind-mounted from the host cache.
exec '{CLAUDE_BINARY_CONTAINER_PATH}' "$@"
"""
)

# The passthrough entrypoint script content.  Same setup as the agent
# entrypoint but runs the command directly instead of Claude.
PASSTHROUGH_ENTRYPOINT_SCRIPT = (
    _SETUP
    + """
# Run command with all arguments passed through
exec "$@"
"""
)


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
