#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Mock podman command for integration tests with state tracking.

Simulates podman's behavior for integration testing, allowing the email
gateway to run without an actual container runtime.  Tracks images,
networks and containers under ``$MOCK_PODMAN_STATE_DIR`` so that
commands like ``podman network ls`` and ``podman ps`` return consistent
results across invocations:

- ``networks/<name>`` and ``containers/<name>``: one file per network
  and container, so concurrent invocations never lose each other's
  changes.
- ``builds/<tag>.json``: the build context of each image built, which
  also marks the image as existing for ``podman image inspect``.

Nothing is tracked when the environment variable is unset.

Invocation:
    python -S -m tests.integration.gateway.mock_podman <args>

Environment Variables:
    MOCK_PODMAN_STATE_DIR: Directory for persistent state.
    All MOCK_CLAUDE_* variables are passed through to mock_claude.py.
    See mock_claude.py for details on response strategies.
"""

# The gateway spawns this script thousands of times per integration run,
# so its startup time is a large share of the suite's run time.  The
# commands run most often need only these modules; json, pathlib and
# mock_claude add ~20ms to every process and are imported by the
# commands that use them.
import os
import sys
import time


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def _state_dir(kind: str) -> str | None:
    """Return the directory tracking *kind*, or None if state is untracked.

    Args:
        kind: ``networks``, ``containers`` or ``builds``.
    """
    root = os.environ.get("MOCK_PODMAN_STATE_DIR")
    if not root:
        return None
    return os.path.join(root, kind)


def _add(kind: str, name: str) -> None:
    """Record that the *kind* object *name* exists."""
    directory = _state_dir(kind)
    if directory is None:
        return
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, name), "w"):
        pass


def _remove(kind: str, name: str) -> None:
    """Record that the *kind* object *name* no longer exists."""
    directory = _state_dir(kind)
    if directory is None:
        return
    try:
        os.unlink(os.path.join(directory, name))
    except FileNotFoundError:
        pass


def _exists(kind: str, name: str) -> bool:
    """Return whether the *kind* object *name* exists."""
    directory = _state_dir(kind)
    return directory is not None and os.path.isfile(
        os.path.join(directory, name)
    )


def _list(kind: str, prefix: str | None) -> list[str]:
    """Return the names of *kind* objects, optionally only with *prefix*."""
    directory = _state_dir(kind)
    try:
        names = os.listdir(directory) if directory else []
    except FileNotFoundError:
        names = []
    return sorted(n for n in names if prefix is None or n.startswith(prefix))


def _build_record(tag: str) -> str | None:
    """Return where the build of *tag* is recorded, or None if untracked."""
    directory = _state_dir("builds")
    if directory is None:
        return None
    return os.path.join(directory, f"{tag.replace(':', '_')}.json")


def _name_filter(args: list[str]) -> str | None:
    """Return the prefix of a ``--filter name=<prefix>`` option in *args*."""
    for i, arg in enumerate(args):
        if arg == "--filter" and i + 1 < len(args):
            filt = args[i + 1]
            if filt.startswith("name="):
                return filt[len("name=") :]
    return None


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def handle_image_inspect(args: list[str]) -> int:
    """Handle 'podman image inspect <tag> --format {{.Created}}'.

    Like podman, fails for an image that does not exist, so the gateway's
    image cache builds an image once and reuses it afterwards.  For an
    image built by :func:`handle_build`, prints the build time in Go's
    ``time.Time.String()`` format, as podman does.
    """
    if len(args) != 3 or args[1:] != ["--format", "{{.Created}}"]:
        print(
            f"mock_podman: image inspect: unsupported: {args}", file=sys.stderr
        )
        return 125

    tag = args[0]
    record = _build_record(tag)
    try:
        created_ns = os.stat(record).st_mtime_ns if record else None
    except FileNotFoundError:
        created_ns = None
    if created_ns is None:
        print(f"Error: {tag}: image not known", file=sys.stderr)
        return 125

    seconds, nanos = divmod(created_ns, 1_000_000_000)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds))
    # Go omits trailing zeros of the fraction, and the fraction if zero.
    fraction = f"{nanos:09d}".rstrip("0")
    if fraction:
        stamp += f".{fraction}"
    print(f"{stamp} +0000 UTC")
    return 0


def handle_build(args: list[str]) -> int:
    """Handle 'podman build' – record the build context, pretend success.

    Writes ``builds/<tag>.json`` in the state directory, mapping each
    file in the build context directory (the last argument) to its text
    content and executable bit, so tests can check what an image would
    have been built from.  The record is written atomically: podman
    shows an image only once its build has finished.
    """
    if "-t" not in args:
        return 0
    tag = args[args.index("-t") + 1]
    record = _build_record(tag)
    if record is None:
        return 0

    import json
    from pathlib import Path

    context = Path(args[-1])
    files = {
        f.relative_to(context).as_posix(): {
            "content": f.read_text(errors="replace"),
            "executable": bool(f.stat().st_mode & 0o111),
        }
        for f in sorted(context.rglob("*"))
        if f.is_file()
    }
    os.makedirs(os.path.dirname(record), exist_ok=True)
    tmp = f"{record}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(files, f)
    os.replace(tmp, record)
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
    _add("containers", name)
    print(f"mock-{name}-{os.getpid()}")
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

    from . import mock_claude

    return mock_claude.main()


def handle_rm(args: list[str]) -> int:
    """Handle 'podman rm' – remove container from state."""
    for arg in args:
        if not arg.startswith("-"):
            _remove("containers", arg)
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
    _add("networks", args[-1] if args else f"net-{int(time.time())}")
    return 0


def _handle_network_rm(args: list[str]) -> int:
    """Remove a network from state (supports -f flag)."""
    for arg in args:
        if not arg.startswith("-"):
            _remove("networks", arg)
    return 0


def _handle_network_ls(args: list[str]) -> int:
    """List networks, supporting ``--filter name=prefix``."""
    for net in _list("networks", _name_filter(args)):
        print(net)
    return 0


def _handle_network_exists(args: list[str]) -> int:
    """Check if a network exists (exit 0 = yes, 1 = no)."""
    return 0 if args and _exists("networks", args[-1]) else 1


# ---------------------------------------------------------------------------
# Container inspection helpers
# ---------------------------------------------------------------------------


def handle_ps(args: list[str]) -> int:
    """List containers, supporting ``--filter name=prefix``."""
    for name in _list("containers", _name_filter(args)):
        print(name)
    return 0


def handle_container(args: list[str]) -> int:
    """Handle 'podman container' – supports 'exists' subcommand."""
    if not args:
        print("mock_podman: container: missing subcommand", file=sys.stderr)
        return 1

    if args[0] == "exists":
        return 0 if len(args) > 1 and _exists("containers", args[1]) else 1

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
