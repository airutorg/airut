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
    python -m tests.integration.gateway.mock_podman <args>

Environment Variables:
    MOCK_PODMAN_STATE_DIR: Directory for persistent state file.
    All MOCK_CLAUDE_* variables are passed through to mock_claude.py.
    See mock_claude.py for details on response strategies.
"""

import json
import os
import sys
import tempfile
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
    """Load persisted state, returning defaults when absent.

    Retries on transient read failures (empty content, corrupt JSON,
    ``FileNotFoundError``) that can occur when a concurrent process
    is atomically replacing the state file via :func:`os.replace`.
    """
    path = _state_path()
    if path and path.exists():
        for attempt in range(3):
            try:
                data = path.read_text()
                if data:
                    return json.loads(data)
            except (json.JSONDecodeError, OSError):
                pass
            if attempt < 2:
                time.sleep(0.05)
    return {"networks": [], "containers": {}}


def _save_state(state: dict) -> None:
    """Persist *state* to disk atomically (no-op when state dir is unset).

    Writes to a temporary file then uses :func:`os.replace` so that
    concurrent readers never observe a truncated/empty file.
    """
    path = _state_path()
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(state, f)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def handle_image_inspect(args: list[str]) -> int:
    """Handle 'podman image inspect' – always report image exists."""
    print(json.dumps([{"Id": "mock-image-id", "RepoTags": args[-1:]}]))
    return 0


def handle_build(args: list[str]) -> int:
    """Handle 'podman build' – record the build context, pretend success.

    Writes ``builds/<tag>.json`` next to the state file, mapping each
    file in the build context directory (the last argument) to its text
    content and executable bit, so tests can check what an image would
    have been built from.
    """
    path = _state_path()
    if path is None or "-t" not in args:
        return 0
    tag = args[args.index("-t") + 1]
    context = Path(args[-1])
    files = {
        f.relative_to(context).as_posix(): {
            "content": f.read_text(errors="replace"),
            "executable": bool(f.stat().st_mode & 0o111),
        }
        for f in sorted(context.rglob("*"))
        if f.is_file()
    }
    record = path.parent / "builds" / f"{tag.replace(':', '_')}.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(files))
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


# ``podman run`` options that take a separate value.
_RUN_VALUE_OPTIONS = frozenset(
    {
        "-v",
        "-e",
        "--network",
        "--name",
        "--dns",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--pids-limit",
        "--entrypoint",
    }
)

# Claude options (as passed by AgentTask) that take a separate value.
_CLAUDE_VALUE_OPTIONS = frozenset(
    {"--resume", "--model", "--effort", "--output-format"}
)


def _check_claude_args(args: list[str]) -> str | None:
    """Return the session ID from Claude's *args*; reject positionals.

    The real Claude prepends any positional argument to the prompt it
    reads from stdin, so AgentTask must pass options only.

    Raises:
        SystemExit: On a positional argument.
    """
    session_id = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-" or not arg.startswith("-"):
            print(
                f"mock_podman: positional Claude argument {arg!r} would be "
                "prepended to the prompt (if it is an option's value, add "
                "the option to _CLAUDE_VALUE_OPTIONS)",
                file=sys.stderr,
            )
            raise SystemExit(2)
        if arg in _CLAUDE_VALUE_OPTIONS and i + 1 < len(args):
            if arg == "--resume":
                session_id = args[i + 1]
            i += 2
        else:
            i += 1
    return session_id


def _handle_interactive_run(args: list[str]) -> int:
    """Handle interactive run for Claude containers.

    Parses the podman run command for volume mounts (-v), environment
    variables (-e) and the image; everything after the image is the
    container command.  For agent containers (with the Claude binary
    mounted) the command is Claude's arguments, which must be options
    only.  Then delegates to mock_claude.main().
    """
    mounts: dict[str, str] = {}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg in _RUN_VALUE_OPTIONS and i + 1 < len(args):
            value = args[i + 1]
            if arg == "-v":
                parts = value.split(":")
                if len(parts) >= 2:
                    mounts[parts[1]] = parts[0]
            elif arg == "-e" and "=" in value:
                name, env_value = value.split("=", 1)
                os.environ[name] = env_value
            i += 2
        else:
            i += 1  # flag or --option=value
    command = args[i + 1 :]  # args[i] is the image

    # CLAUDE_BINARY_CONTAINER_PATH, spelled out: importing airut.sandbox
    # would slow down every one of the thousands of mock invocations.
    if "/opt/claude/claude" in mounts:
        session_id = _check_claude_args(command)
        if session_id:
            os.environ["MOCK_CLAUDE_SESSION_ID"] = session_id

    for container_path, env_name in (
        ("/workspace", "MOCK_CLAUDE_WORKSPACE"),
        ("/inbox", "MOCK_CLAUDE_INBOX"),
        ("/outbox", "MOCK_CLAUDE_OUTBOX"),
    ):
        if container_path in mounts:
            os.environ[env_name] = mounts[container_path]

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
