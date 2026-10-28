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

Both variants share the same setup: CA trust, then the image's optional
environment hook (``/etc/airut/env.sh``), then re-applying the settings
the hook must not override.  CA trust output goes to stderr when
``AIRUT_VERBOSE=1`` is set in the container environment and is
discarded otherwise.  The hook's own output and warnings always go to
stderr.  Setup never touches the command's stdin or stdout.
"""

from __future__ import annotations

import shlex
import string

from airut.sandbox._network import CA_CONTAINER_PATH, CA_ENV_VARS
from airut.sandbox.claude_binary import CLAUDE_BINARY_CONTAINER_PATH


#: System CA bundle the entrypoint extends with the proxy CA when the
#: image has no ``update-ca-certificates`` (e.g. Nix-based images).
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

#: Optional script an image provides to set up the environment (e.g. a
#: Nix devShell).  Both entrypoints source it before running the command.
ENV_HOOK_PATH = "/etc/airut/env.sh"

# Environment variables airut forces into the container for every Claude
# execution, overriding any caller- or repo-provided values.
#
# ``CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1``: airut runs Claude headlessly
# (``claude -p``), which is single-shot -- the process prints its result and
# exits when the model ends its turn. Background tasks are incompatible with
# that lifecycle: a foreground Bash command that blocks longer than Claude's
# ~15s "assistant-mode blocking budget" is auto-moved to the background and its
# result is delivered as an async notification, but ``-p`` exits (killing the
# task) before that notification can be processed -- so the agent reports
# "standing by" and never sees, e.g., the CI verdict. Disabling background
# tasks makes Bash commands and subagents run synchronously: the turn blocks
# until they finish. Subagents still work; they just run inline rather than
# being backgrounded.
# Ensuring ``claude -p`` behaves correctly is airut's responsibility, not the
# repo's, so this is set by the sandbox rather than relying on the Dockerfile.
# ``AgentTask`` passes these to podman and the agent entrypoint re-applies
# them after the image's environment hook.
FORCED_CLAUDE_ENV: dict[str, str] = {
    "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
}

# Bash words expanding to every variable name: "${!X@}" for each possible
# first character (bash has no portable builtin listing exported
# variables).  Spliced into the hook snapshot function below.
_FIRST_CHARS = string.ascii_uppercase + string.ascii_lowercase + "_"
_ALL_VARIABLE_NAMES = " \\\n        ".join(
    " ".join(f'"${{!{c}@}}"' for c in _FIRST_CHARS[i : i + 9])
    for i in range(0, len(_FIRST_CHARS), 9)
)

# Start of the setup shared by both entrypoint variants: header and CA
# trust.  Changes to the generated scripts change the overlay image hash,
# triggering a rebuild.
_PRELUDE = (
    f"""\
#!/usr/bin/env bash
set -euo pipefail

readonly airut_ca='{CA_CONTAINER_PATH}'
readonly airut_bundle='{SYSTEM_CA_BUNDLE}'
readonly airut_env_hook='{ENV_HOOK_PATH}'
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

# Environment hook section of the shared setup.
_ENV_HOOK = r"""
# Write the hook's exported variables to $airut_env_file as declare
# lines that cannot fail when re-read (readonly flags are dropped, errors
# ignored), then an end marker so a truncated file is never imported.
# Variables are listed with ${!X@} rather than compgen, which bash built
# without readline (e.g. nixpkgs' bash) lacks.  Skipped: arrays (never
# exported by bash), namerefs, airut_* (the entrypoint's own, exported by
# a hook's set -a), and PWD, OLDPWD, SHLVL and _ (which describe the
# hook's shell, not the command's).  Clears the EXIT trap first, so it runs
# once and the hook's own EXIT traps do not tear down services it started
# for the command.
airut_snapshot() {
    trap - DEBUG RETURN ERR
    set +eux
    trap - EXIT
    local airut_name airut_attrs
    for airut_name in @ALL_VARIABLE_NAMES@; do
        airut_attrs=${!airut_name@a}
        case $airut_attrs in *x*) ;; *) continue ;; esac
        case $airut_attrs in *[aA]*) continue ;; esac
        case $airut_name in PWD | OLDPWD | SHLVL | _ | airut_*) continue ;; esac
        [[ -R $airut_name ]] && continue
        builtin printf 'declare -x %s=%q 2>/dev/null || :\n' \
            "$airut_name" "${!airut_name}"
    done >|"$airut_env_file"
    builtin printf '%s\n' "$airut_env_end" >>"$airut_env_file"
}

# Load the image's environment hook, if any.  The hook is sourced in a
# subshell, with no arguments, stdin from /dev/null and stdout sent to
# stderr, so nothing it does (exit, exec, set -e/-u failures, cd, traps)
# can stop the command from starting or touch its input and output.
# Its exported variables are imported from the snapshot written when the
# hook returns or exits.  Failures only warn.
if [ -f "$airut_env_hook" ]; then
    case ${TMPDIR:-} in
    /*) [ -d "$TMPDIR" ] && airut_env_file=$TMPDIR || airut_env_file=/tmp ;;
    *) airut_env_file=/tmp ;;
    esac
    readonly airut_env_file="$airut_env_file/airut-env.$$.$RANDOM$RANDOM"
    readonly airut_env_end='# airut: end of environment'
    set +e
    (
        set +u +o pipefail
        set --
        trap airut_snapshot EXIT
        . "$airut_env_hook"
        airut_status=$?
        airut_snapshot
        exit "$airut_status"
    ) </dev/null >&2
    airut_status=$?
    set -e
    if [ "$airut_status" -ne 0 ]; then
        echo "airut: warning: $airut_env_hook exited with status" \
            "$airut_status; continuing" >&2
    fi
    # Read and delete the snapshot before importing it: afterwards PATH
    # is the hook's, and only builtins are safe to use.
    airut_env=
    if [ -f "$airut_env_file" ]; then
        airut_env=$(<"$airut_env_file") || airut_env=
        rm -f "$airut_env_file" || true
    fi
    case $airut_env in
    *"$airut_env_end")
        eval "$airut_env" || echo "airut: warning: importing the" \
            "environment set by $airut_env_hook failed" >&2
        ;;
    *)
        echo "airut: warning: could not capture the environment" \
            "set by $airut_env_hook; continuing without it" >&2
        ;;
    esac
    unset airut_env
fi

# Re-apply settings the environment hook must not override (a Nix
# devShell with cacert, for example, resets NIX_SSL_CERT_FILE).
export IS_SANDBOX=1
if [ -f "$airut_ca" ]; then
@EXPORT_CA_ENV_VARS@
fi
""".replace("@ALL_VARIABLE_NAMES@", _ALL_VARIABLE_NAMES).replace(
    "@EXPORT_CA_ENV_VARS@",
    "\n".join(f'    export {var}="$airut_ca"' for var in CA_ENV_VARS),
)

# Setup shared by both entrypoint variants.
_SETUP = _PRELUDE + _ENV_HOOK

# The agent entrypoint script content.
AGENT_ENTRYPOINT_SCRIPT = (
    _SETUP
    + f"""
# Re-apply the settings Airut forces for every Claude run, which the
# environment hook must not override either.
@EXPORT_FORCED_CLAUDE_ENV@

# Run Claude Code with all arguments passed through.  The binary is
# bind-mounted from the host cache.  If it cannot be executed, add the
# likely cause to bash's error message.
airut_claude='{CLAUDE_BINARY_CONTAINER_PATH}'
set +e
shopt -s execfail
exec "$airut_claude" "$@"
airut_status=$?
echo "airut: cannot execute $airut_claude (status $airut_status)" >&2
if [ "$airut_status" -eq 127 ] && [ -e "$airut_claude" ]; then
    echo "airut: the binary exists, so the image most likely lacks the" \\
        "dynamic loader it needs at its standard path (or has a dangling" \\
        "symlink there), e.g." \\
        "/lib64/ld-linux-x86-64.so.2 (glibc, x86_64)," \\
        "/lib/ld-linux-aarch64.so.1 (glibc, arm64) or" \\
        "/lib/ld-musl-<arch>.so.1 (musl hosts)" >&2
fi
exit "$airut_status"
""".replace(
        "@EXPORT_FORCED_CLAUDE_ENV@",
        "\n".join(
            f"export {name}={shlex.quote(value)}"
            for name, value in FORCED_CLAUDE_ENV.items()
        ),
    )
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
