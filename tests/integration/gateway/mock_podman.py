#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Mock podman command for integration tests with state tracking.

Simulates podman's behavior for integration testing, allowing the email
gateway to run without an actual container runtime. Tracks networks,
containers, and proxy processes in a JSON state file so that commands
like ``podman network ls`` and ``podman ps`` return consistent results
across invocations.

State is stored in ``$MOCK_PODMAN_STATE_DIR/state.json`` when the
environment variable is set.

Invocation:
    python -m tests.integration.mock_podman <args>

Environment Variables:
    MOCK_PODMAN_STATE_DIR: Directory for persistent state file.
    All MOCK_CLAUDE_* variables are passed through to mock_claude.py.
    See mock_claude.py for details on response strategies.
"""

import json
import os
import sys
import time
from pathlib import Path

# Import mock_claude from same package
from . import mock_claude


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def _state_path() -> Path | None:
    """Return the path to the state file, or None if not configured."""
    state_dir = os.environ.get("MOCK_PODMAN_STATE_DIR")
    if not state_dir:
        return None
    return Path(state_dir) / "state.json"


def _load_state() -> dict:
    """Load persisted state, returning defaults when absent."""
    path = _state_path()
    if path and path.exists():
        return json.loads(path.read_text())
    return {"networks": [], "containers": {}}


def _save_state(state: dict) -> None:
    """Persist *state* to disk (no-op when state dir is unset)."""
    path = _state_path()
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state))


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def handle_image_inspect(args: list[str]) -> int:
    """Handle 'podman image inspect' – always report image exists."""
    print(json.dumps([{"Id": "mock-image-id", "RepoTags": args[-1:]}]))
    return 0


def handle_build(args: list[str]) -> int:
    """Handle 'podman build' – no-op, pretend success."""
    return 0


def handle_run(args: list[str]) -> int:
    """Handle 'podman run' – dispatch to detached or interactive."""
    if "-d" in args:
        return _handle_detached_run(args)
    return _handle_interactive_run(args)


def _extract_name(args: list[str]) -> str | None:
    """Extract the ``--name`` value from *args*."""
    for i, arg in enumerate(args):
        if arg == "--name" and i + 1 < len(args):
            return args[i + 1]
    return None


def _handle_detached_run(args: list[str]) -> int:
    """Record a mock container in state (no real process needed)."""
    name = _extract_name(args) or f"container-{int(time.time())}"

    state = _load_state()
    container_id = f"mock-{name}-{os.getpid()}"
    state["containers"][name] = container_id
    _save_state(state)

    print(container_id)
    return 0


def _handle_interactive_run(args: list[str]) -> int:
    """Handle interactive run for Claude containers.

    Parses the podman run command to find volume mounts (-v),
    environment variables (-e), and other flags, then delegates
    to mock_claude.main().
    """
    workspace = None
    inbox = None
    outbox = None

    i = 0

    while i < len(args):
        arg = args[i]

        if arg == "-v" and i + 1 < len(args):
            mount = args[i + 1]
            parts = mount.split(":")
            if len(parts) >= 2:
                if parts[1] == "/workspace":
                    workspace = parts[0]
                elif parts[1] == "/inbox":
                    inbox = parts[0]
                elif parts[1] == "/outbox":
                    outbox = parts[0]

            i += 2

        elif arg == "-e" and i + 1 < len(args):
            env_spec = args[i + 1]
            if "=" in env_spec:
                name, value = env_spec.split("=", 1)
                os.environ[name] = value
            i += 2

        elif arg in ("--rm", "-i"):
            i += 1

        elif arg.startswith("--log-driver="):
            i += 1

        elif arg == "--network" and i + 1 < len(args):
            i += 2

        elif arg == "--name" and i + 1 < len(args):
            i += 2

        else:
            remaining = args[i:]
            if remaining and not remaining[0].startswith("-"):
                remaining = remaining[1:]

            session_id = None
            j = 0
            while j < len(remaining):
                if remaining[j] == "--resume" and j + 1 < len(remaining):
                    session_id = remaining[j + 1]
                    j += 2
                else:
                    j += 1

            if session_id:
                os.environ["MOCK_CLAUDE_SESSION_ID"] = session_id
            break

    if workspace:
        os.environ["MOCK_CLAUDE_WORKSPACE"] = workspace
    if inbox:
        os.environ["MOCK_CLAUDE_INBOX"] = inbox
    if outbox:
        os.environ["MOCK_CLAUDE_OUTBOX"] = outbox

    return mock_claude.main()


def handle_rm(args: list[str]) -> int:
    """Handle 'podman rm' – remove container from state."""
    state = _load_state()
    for arg in args:
        if arg.startswith("-"):
            continue
        state["containers"].pop(arg, None)
    _save_state(state)
    return 0


def handle_stop(args: list[str]) -> int:
    """Handle 'podman stop' – no-op, return success."""
    return 0


def handle_exec(args: list[str]) -> int:
    """Handle 'podman exec' – always succeed (mock containers are healthy)."""
    return 0


# ---------------------------------------------------------------------------
# Network sub-commands
# ---------------------------------------------------------------------------


def handle_network(args: list[str]) -> int:
    """Handle 'podman network' – dispatch to subcommand."""
    if not args:
        print("mock_podman: network: missing subcommand", file=sys.stderr)
        return 1

    sub = args[0]
    rest = args[1:]

    dispatch = {
        "create": _handle_network_create,
        "rm": _handle_network_rm,
        "ls": _handle_network_ls,
        "exists": _handle_network_exists,
    }

    handler = dispatch.get(sub)
    if handler is None:
        print(
            f"mock_podman: network: unknown subcommand: {sub}",
            file=sys.stderr,
        )
        return 1
    return handler(rest)


def _handle_network_create(args: list[str]) -> int:
    """Create a network and track it in state."""
    name = args[-1] if args else f"net-{int(time.time())}"
    state = _load_state()
    if name not in state["networks"]:
        state["networks"].append(name)
    _save_state(state)
    return 0


def _handle_network_rm(args: list[str]) -> int:
    """Remove a network from state (supports -f flag)."""
    names = [a for a in args if not a.startswith("-")]
    state = _load_state()
    for name in names:
        if name in state["networks"]:
            state["networks"].remove(name)
    _save_state(state)
    return 0


def _handle_network_ls(args: list[str]) -> int:
    """List networks, supporting ``--filter name=prefix``."""
    prefix = None
    for i, arg in enumerate(args):
        if arg == "--filter" and i + 1 < len(args):
            filt = args[i + 1]
            if filt.startswith("name="):
                prefix = filt[len("name=") :]

    state = _load_state()
    for net in state["networks"]:
        if prefix is None or net.startswith(prefix):
            print(net)
    return 0


def _handle_network_exists(args: list[str]) -> int:
    """Check if a network exists (exit 0 = yes, 1 = no)."""
    name = args[-1] if args else ""
    state = _load_state()
    return 0 if name in state["networks"] else 1


# ---------------------------------------------------------------------------
# Container inspection helpers
# ---------------------------------------------------------------------------


def handle_ps(args: list[str]) -> int:
    """List containers, supporting ``--filter name=prefix``."""
    prefix = None
    for i, arg in enumerate(args):
        if arg == "--filter" and i + 1 < len(args):
            filt = args[i + 1]
            if filt.startswith("name="):
                prefix = filt[len("name=") :]

    state = _load_state()
    for name in state["containers"]:
        if prefix is None or name.startswith(prefix):
            print(name)
    return 0


def handle_container(args: list[str]) -> int:
    """Handle 'podman container' – supports 'exists' subcommand."""
    if not args:
        print("mock_podman: container: missing subcommand", file=sys.stderr)
        return 1

    if args[0] == "exists":
        name = args[1] if len(args) > 1 else ""
        state = _load_state()
        return 0 if name in state["containers"] else 1

    print(
        f"mock_podman: container: unknown subcommand: {args[0]}",
        file=sys.stderr,
    )
    return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Main entry point for mock podman."""
    args = sys.argv[1:]

    if not args:
        print("mock_podman: missing command", file=sys.stderr)
        return 1

    cmd = args[0]
    rest = args[1:]

    if cmd == "image" and len(rest) >= 1 and rest[0] == "inspect":
        return handle_image_inspect(rest[1:])

    if cmd == "build":
        return handle_build(rest)

    if cmd == "run":
        return handle_run(rest)

    if cmd == "rm":
        return handle_rm(rest)

    if cmd == "stop":
        return handle_stop(rest)

    if cmd == "exec":
        return handle_exec(rest)

    if cmd == "network":
        return handle_network(rest)

    if cmd == "ps":
        return handle_ps(rest)

    if cmd == "container":
        return handle_container(rest)

    print(f"mock_podman: unknown command: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
