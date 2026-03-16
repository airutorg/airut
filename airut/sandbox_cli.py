# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""CLI entry point for ``airut-sandbox``.

Runs arbitrary commands inside the Airut sandbox (container isolation,
network allowlisting, credential masking).  Designed for CI pipelines
but works anywhere with a container runtime.

Usage::

    airut-sandbox run [OPTIONS] -- COMMAND [ARGS...]

Zero coupling to the gateway: imports only from ``airut.sandbox``,
``airut.allowlist``, and ``airut.yaml_env``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import signal
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import yaml

from airut.allowlist import Allowlist, parse_allowlist_yaml
from airut.sandbox import (
    CommandResult,
    ContainerEnv,
    MaskedSecret,
    Mount,
    NetworkSandboxConfig,
    PreparedSecrets,
    ResourceLimits,
    Sandbox,
    SandboxConfig,
    SigningCredential,
    prepare_secrets,
)
from airut.sandbox.task import CommandTask
from airut.yaml_env import EnvVar, make_env_loader, raw_resolve


logger = logging.getLogger(__name__)

#: Exit code for infrastructure errors (matches ``docker run``).
EXIT_INFRA_ERROR = 125

#: Exit code for timeout (matches ``timeout(1)``).
EXIT_TIMEOUT = 124


class _ConfigError(Exception):
    """Sandbox CLI configuration error."""


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------


@dataclass(frozen=True)
class _SandboxCliConfig:
    """Parsed ``.airut/sandbox.yaml`` configuration."""

    env: dict[str, str] = field(default_factory=dict)
    pass_env: list[str] = field(default_factory=list)
    masked_secrets: list[MaskedSecret] = field(default_factory=list)
    signing_credentials: list[SigningCredential] = field(default_factory=list)
    network_sandbox: bool = True
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)


def _require_env(value: object, path: str) -> str:
    """Resolve an ``!env`` value, failing closed on missing vars.

    Args:
        value: Raw YAML value (may be ``EnvVar``).
        path: Config path for error messages.

    Returns:
        Resolved string value.

    Raises:
        _ConfigError: If the env var is not set.
    """
    resolved = raw_resolve(value)
    if resolved is None:
        if isinstance(value, EnvVar):
            raise _ConfigError(
                f"{path}: environment variable '{value.var_name}' is not set"
            )
        raise _ConfigError(f"{path}: value is missing")
    return resolved


def _load_config(config_path: Path) -> _SandboxCliConfig:
    """Load and resolve ``.airut/sandbox.yaml``.

    Args:
        config_path: Path to the config file.

    Returns:
        Parsed configuration.

    Raises:
        _ConfigError: On invalid config or missing env vars.
    """
    if not config_path.exists():
        logger.debug("Config file not found: %s (using defaults)", config_path)
        return _SandboxCliConfig()

    try:
        with open(config_path) as f:
            raw = yaml.load(f, Loader=make_env_loader())
    except yaml.YAMLError as e:
        raise _ConfigError(f"Invalid YAML in {config_path}: {e}") from e

    if raw is None:
        return _SandboxCliConfig()

    if not isinstance(raw, dict):
        raise _ConfigError(f"Config file must be a YAML mapping: {config_path}")

    cfg = cast(dict[str, object], raw)
    return _SandboxCliConfig(
        env=_parse_env(cfg.get("env")),
        pass_env=_parse_pass_env(cfg.get("pass_env")),
        masked_secrets=_parse_masked_secrets(cfg.get("masked_secrets")),
        signing_credentials=_parse_signing_credentials(
            cfg.get("signing_credentials")
        ),
        network_sandbox=_parse_network_sandbox(cfg.get("network_sandbox")),
        resource_limits=_parse_resource_limits(cfg.get("resource_limits")),
    )


def _parse_env(raw: object) -> dict[str, str]:
    """Parse the ``env:`` section (static key-value pairs).

    Values may use ``!env`` tags, which are resolved here.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise _ConfigError("'env' must be a mapping")
    d = cast(dict[str, object], raw)
    result: dict[str, str] = {}
    for k, v in d.items():
        key = str(k)
        result[key] = _require_env(v, f"env.{key}")
    return result


def _parse_pass_env(raw: object) -> list[str]:
    """Parse the ``pass_env:`` section (list of env var names)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise _ConfigError("'pass_env' must be a list")
    return [str(item) for item in raw]


def _parse_masked_secrets(raw: object) -> list[MaskedSecret]:
    """Parse the ``masked_secrets:`` section."""
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise _ConfigError("'masked_secrets' must be a mapping")

    d = cast(dict[str, object], raw)
    result: list[MaskedSecret] = []
    for name, config in d.items():
        name = str(name)
        path = f"masked_secrets.{name}"

        if not isinstance(config, dict):
            raise _ConfigError(f"{path} must be a mapping")

        c = cast(dict[str, object], config)
        value = _require_env(c.get("value"), f"{path}.value")

        raw_scopes = c.get("scopes")
        if not isinstance(raw_scopes, list) or not raw_scopes:
            raise _ConfigError(f"{path}.scopes must be a non-empty list")

        raw_headers = c.get("headers")
        if not isinstance(raw_headers, list) or not raw_headers:
            raise _ConfigError(f"{path}.headers must be a non-empty list")

        allow_foreign = bool(c.get("allow_foreign_credentials", False))

        result.append(
            MaskedSecret(
                env_var=name,
                real_value=value,
                scopes=tuple(str(s) for s in raw_scopes),
                headers=tuple(str(h) for h in raw_headers),
                allow_foreign_credentials=allow_foreign,
            )
        )
    return result


def _parse_signing_credentials(raw: object) -> list[SigningCredential]:
    """Parse the ``signing_credentials:`` section."""
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise _ConfigError("'signing_credentials' must be a mapping")

    d = cast(dict[str, object], raw)
    result: list[SigningCredential] = []
    for name, config in d.items():
        name = str(name)
        path = f"signing_credentials.{name}"

        if not isinstance(config, dict):
            raise _ConfigError(f"{path} must be a mapping")

        c = cast(dict[str, object], config)
        cred_type = c.get("type")
        if cred_type != "aws-sigv4":
            raise _ConfigError(
                f"{path}.type must be 'aws-sigv4', got {cred_type!r}"
            )

        access_key_id = _require_env(
            c.get("access_key_id"), f"{path}.access_key_id"
        )
        secret_access_key = _require_env(
            c.get("secret_access_key"),
            f"{path}.secret_access_key",
        )

        # Derive env var names from the !env tag variable names,
        # or use the field key if the value is a plain string.
        aki_raw = c.get("access_key_id")
        sak_raw = c.get("secret_access_key")
        st_raw = c.get("session_token")

        aki_env = (
            aki_raw.var_name
            if isinstance(aki_raw, EnvVar)
            else "AWS_ACCESS_KEY_ID"
        )
        sak_env = (
            sak_raw.var_name
            if isinstance(sak_raw, EnvVar)
            else "AWS_SECRET_ACCESS_KEY"
        )

        session_token: str | None = None
        session_token_env: str | None = None
        if st_raw is not None:
            session_token = _require_env(st_raw, f"{path}.session_token")
            session_token_env = (
                st_raw.var_name
                if isinstance(st_raw, EnvVar)
                else "AWS_SESSION_TOKEN"
            )

        raw_scopes = c.get("scopes")
        if not isinstance(raw_scopes, list) or not raw_scopes:
            raise _ConfigError(f"{path}.scopes must be a non-empty list")

        result.append(
            SigningCredential(
                access_key_id_env_var=aki_env,
                access_key_id=access_key_id,
                secret_access_key_env_var=sak_env,
                secret_access_key=secret_access_key,
                session_token_env_var=session_token_env,
                session_token=session_token,
                scopes=tuple(str(s) for s in raw_scopes),
            )
        )
    return result


def _parse_network_sandbox(raw: object) -> bool:
    """Parse the ``network_sandbox:`` field (default True)."""
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    s = str(raw).lower().strip()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    raise _ConfigError(f"'network_sandbox' must be a boolean, got {raw!r}")


def _parse_resource_limits(raw: object) -> ResourceLimits:
    """Parse the ``resource_limits:`` section."""
    if raw is None:
        return ResourceLimits()
    if not isinstance(raw, dict):
        raise _ConfigError("'resource_limits' must be a mapping")

    d = cast(dict[str, object], raw)
    raw_timeout = d.get("timeout")
    raw_memory = d.get("memory")
    raw_cpus = d.get("cpus")
    raw_pids = d.get("pids_limit")

    try:
        return ResourceLimits(
            timeout=(
                int(str(raw_timeout)) if raw_timeout is not None else None
            ),
            memory=str(raw_memory) if raw_memory is not None else None,
            cpus=(float(str(raw_cpus)) if raw_cpus is not None else None),
            pids_limit=(int(str(raw_pids)) if raw_pids is not None else None),
        )
    except (ValueError, TypeError) as e:
        raise _ConfigError(f"'resource_limits' has invalid value: {e}") from e


# -------------------------------------------------------------------
# CLI argument parsing
# -------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments.

    Splits on ``--`` to separate airut-sandbox options from the command.

    Args:
        argv: Command-line arguments (without program name).

    Returns:
        Parsed namespace with ``command`` attribute.
    """
    if "--" in argv:
        idx = argv.index("--")
        our_args = argv[:idx]
        command = argv[idx + 1 :]
    else:
        our_args = argv
        command = []

    parser = argparse.ArgumentParser(
        prog="airut-sandbox",
        description="Run commands inside the Airut sandbox.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")
    run_parser = subparsers.add_parser(
        "run", help="Run a command in the sandbox"
    )
    run_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Sandbox config (default: .airut/sandbox.yaml)",
    )
    run_parser.add_argument(
        "--dockerfile",
        type=Path,
        default=None,
        help="Path to Dockerfile (default: .airut/container/Dockerfile)",
    )
    run_parser.add_argument(
        "--context-dir",
        type=Path,
        default=None,
        help="Build context directory (default: .airut/container/)",
    )
    run_parser.add_argument(
        "--allowlist",
        type=Path,
        default=None,
        help="Network allowlist override",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Container timeout (overrides config)",
    )
    run_parser.add_argument(
        "--container-command",
        default=None,
        help="Container runtime (default: podman)",
    )
    run_parser.add_argument(
        "--mount",
        action="append",
        default=[],
        help="Additional mount SRC:DST[:ro] (repeatable)",
    )
    run_parser.add_argument(
        "--network-log",
        type=Path,
        default=None,
        help="Append network activity log to FILE",
    )
    run_parser.add_argument(
        "--log",
        type=Path,
        default=None,
        help="Write sandbox log to FILE instead of stderr",
    )
    run_parser.add_argument(
        "--network-log-live",
        action="store_true",
        help="Print network activity to stderr during execution",
    )
    run_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable informational logging (INFO level)",
    )
    run_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (DEBUG level, implies --verbose)",
    )

    args = parser.parse_args(our_args)
    args.command = command
    return args


# -------------------------------------------------------------------
# Mount parsing
# -------------------------------------------------------------------


def _parse_mount(mount_str: str) -> Mount:
    """Parse a ``--mount SRC:DST[:ro]`` argument.

    Args:
        mount_str: Mount specification string.

    Returns:
        Parsed Mount.

    Raises:
        _ConfigError: If the format is invalid.
    """
    parts = mount_str.split(":")
    if len(parts) == 2:
        return Mount(
            host_path=Path(parts[0]).resolve(),
            container_path=parts[1],
        )
    if len(parts) == 3 and parts[2] == "ro":
        return Mount(
            host_path=Path(parts[0]).resolve(),
            container_path=parts[1],
            read_only=True,
        )
    raise _ConfigError(
        f"Invalid mount format: '{mount_str}' (expected SRC:DST or SRC:DST:ro)"
    )


# -------------------------------------------------------------------
# Logging setup
# -------------------------------------------------------------------


def _setup_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    log_file: Path | None = None,
) -> None:
    """Configure logging.

    The default level is ERROR so that only the sandboxed command's
    stdout/stderr appear on the terminal.  ``--verbose`` enables INFO
    messages (startup, image build, shutdown), and ``--debug`` enables
    DEBUG messages (full command lines, internal details).

    When *log_file* is ``None``, logs are written to stderr.  When
    given, logs are appended to the specified file instead (parent
    directories are created automatically).

    Args:
        verbose: Enable INFO-level output.
        debug: Enable DEBUG-level output (implies verbose).
        log_file: Optional file path for log output.
    """
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.ERROR

    handler: logging.Handler
    if log_file is not None:
        log_file = log_file.resolve()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(log_file), mode="a")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


# -------------------------------------------------------------------
# Network log setup
# -------------------------------------------------------------------


def _setup_network_log(
    user_path: Path | None,
) -> tuple[Path, Callable[[], None]]:
    """Set up the network log file path.

    Args:
        user_path: User-specified ``--network-log`` path, or ``None``
            for a tempfile that is deleted on exit.

    Returns:
        Tuple of (network_log_path, cleanup_fn).
    """
    if user_path is not None:
        user_path = user_path.resolve()
        user_path.parent.mkdir(parents=True, exist_ok=True)
        user_path.touch(exist_ok=True)

        def cleanup() -> None:
            pass  # user file persists

        return user_path, cleanup

    # Default: temp file, deleted on exit
    fd, tmp = tempfile.mkstemp(prefix="airut-netlog-", suffix=".log")
    os.close(fd)
    tmp_path = Path(tmp)

    def cleanup_default() -> None:
        tmp_path.unlink(missing_ok=True)

    return tmp_path, cleanup_default


def _make_network_line_callback() -> Callable[[str], None]:
    """Create a callback that prints network log lines to stderr.

    Returns:
        Callback suitable for ``on_network_line``.
    """

    def on_network_line(line: str) -> None:
        sys.stderr.write(f"[net] {line}\n")
        sys.stderr.flush()

    return on_network_line


# -------------------------------------------------------------------
# Allowlist loading
# -------------------------------------------------------------------


def _load_allowlist(
    allowlist_path: Path, network_sandbox: bool
) -> Allowlist | None:
    """Load the network allowlist.

    Args:
        allowlist_path: Path to the allowlist YAML file.
        network_sandbox: Whether network sandbox is enabled.

    Returns:
        Parsed allowlist, or ``None`` if sandbox is disabled.

    Raises:
        _ConfigError: If the file is invalid.
    """
    if not network_sandbox:
        return None

    if not allowlist_path.exists():
        logger.debug(
            "Allowlist file not found: %s (using empty allowlist)",
            allowlist_path,
        )
        return parse_allowlist_yaml(b"")

    data = allowlist_path.read_bytes()
    try:
        return parse_allowlist_yaml(data)
    except ValueError as e:
        raise _ConfigError(f"Invalid allowlist: {allowlist_path}: {e}") from e


# -------------------------------------------------------------------
# Container environment
# -------------------------------------------------------------------


def _build_container_env(
    config: _SandboxCliConfig,
    prepared: PreparedSecrets,
) -> ContainerEnv:
    """Build the container environment from config and prepared secrets.

    Merging order (later wins):

    1. Static ``env:`` from config
    2. ``pass_env:`` from host environment
    3. Surrogate env vars from ``prepare_secrets()``

    Args:
        config: Parsed sandbox CLI config.
        prepared: Result from ``prepare_secrets()``.

    Returns:
        ContainerEnv for the sandbox task.
    """
    variables: dict[str, str] = {}

    # Static env vars
    variables.update(config.env)

    # Pass-through env vars from host
    for var_name in config.pass_env:
        value = os.environ.get(var_name)
        if value is not None:
            variables[var_name] = value

    # Surrogate env vars from secret masking
    variables.update(prepared.env_vars)

    return ContainerEnv(variables=variables)


# -------------------------------------------------------------------
# Execution orchestration
# -------------------------------------------------------------------


async def _execute_async(
    args: argparse.Namespace, config: _SandboxCliConfig
) -> int:
    """Async orchestration of sandbox lifecycle and command execution.

    Args:
        args: Parsed CLI arguments.
        config: Parsed sandbox configuration.

    Returns:
        Exit code for the CLI process.
    """
    if not args.command:
        logger.error("No command specified after --")
        return EXIT_INFRA_ERROR

    # Resolve paths
    dockerfile_path = args.dockerfile or Path(".airut/container/Dockerfile")
    context_dir = args.context_dir or dockerfile_path.parent
    allowlist_path = args.allowlist or Path(".airut/network-allowlist.yaml")

    # Apply CLI timeout override
    resource_limits = config.resource_limits
    if args.timeout is not None:
        resource_limits = ResourceLimits(
            timeout=args.timeout,
            memory=resource_limits.memory,
            cpus=resource_limits.cpus,
            pids_limit=resource_limits.pids_limit,
        )

    # Load Dockerfile
    if not dockerfile_path.exists():
        logger.error("Dockerfile not found: %s", dockerfile_path)
        return EXIT_INFRA_ERROR

    dockerfile = dockerfile_path.read_bytes()

    # Load context files
    context_files: dict[str, bytes] = {}
    if context_dir.is_dir():
        for child in sorted(context_dir.iterdir()):
            if child.is_file() and child.name != "Dockerfile":
                context_files[child.name] = child.read_bytes()

    # Load allowlist
    try:
        allowlist = _load_allowlist(allowlist_path, config.network_sandbox)
    except _ConfigError as e:
        logger.error("%s", e)
        return EXIT_INFRA_ERROR

    # Prepare secrets
    prepared = prepare_secrets(
        config.masked_secrets, config.signing_credentials
    )

    # Build container env
    container_env = _build_container_env(config, prepared)

    # Pass AIRUT_VERBOSE=1 to the container entrypoint when verbose/debug
    if getattr(args, "verbose", False) or getattr(args, "debug", False):
        container_env = ContainerEnv(
            variables={**container_env.variables, "AIRUT_VERBOSE": "1"}
        )

    # Parse additional mounts
    mounts: list[Mount] = []
    for mount_str in args.mount:
        try:
            mounts.append(_parse_mount(mount_str))
        except _ConfigError as e:
            logger.error("%s", e)
            return EXIT_INFRA_ERROR

    # Default workspace mount: CWD -> /workspace (read-write)
    cwd = Path.cwd().resolve()
    mounts.insert(0, Mount(host_path=cwd, container_path="/workspace"))

    # Network sandbox config
    network_sandbox_config: NetworkSandboxConfig | None = None
    if config.network_sandbox and allowlist is not None:
        network_sandbox_config = NetworkSandboxConfig(
            allowlist=allowlist,
            replacements=prepared.replacements,
        )

    # Set up network log
    network_log_path: Path | None = None

    def _noop_cleanup() -> None:
        pass

    network_log_cleanup: Callable[[], None] = _noop_cleanup
    if config.network_sandbox:
        network_log_path, network_log_cleanup = _setup_network_log(
            args.network_log
        )
        logger.info("Network activity log: %s", network_log_path)

    # Container runtime
    container_command = args.container_command or "podman"

    # Create sandbox with CLI-specific resource prefix to avoid
    # conflicts with the gateway on shared hosts.
    sandbox_config = SandboxConfig(
        container_command=container_command,
        resource_prefix="airut-cli",
    )
    sandbox = Sandbox(sandbox_config)

    execution_context_dir = Path(tempfile.mkdtemp(prefix="airut-exec-"))

    exit_code = EXIT_INFRA_ERROR
    try:
        logger.info("Starting sandbox")
        sandbox.startup()

        try:
            logger.info("Building container image")
            image_tag = sandbox.ensure_image(
                dockerfile,
                context_files,
                passthrough_entrypoint=True,
            )

            logger.info("Creating command task")
            task = sandbox.create_command_task(
                "cli",
                image_tag=image_tag,
                mounts=mounts,
                env=container_env,
                execution_context_dir=execution_context_dir,
                network_log_path=network_log_path,
                network_sandbox=network_sandbox_config,
                resource_limits=resource_limits,
            )

            # Install signal handlers
            _install_signal_handlers(task)

            # Build network log callback
            on_network_line: Callable[[str], None] | None = None
            if getattr(args, "network_log_live", False):
                on_network_line = _make_network_line_callback()

            logger.info("Executing command: %s", args.command)
            result = await task.execute(
                args.command,
                on_output=lambda line: sys.stdout.write(line),
                on_stderr=lambda line: sys.stderr.write(line),
                on_network_line=on_network_line,
            )

            exit_code = _map_exit_code(result)

        finally:
            try:
                logger.info("Shutting down sandbox")
                sandbox.shutdown()
            except Exception as e:
                logger.warning("Sandbox shutdown error: %s", e)

    except Exception as e:
        logger.error("Sandbox infrastructure error: %s", e)
        return EXIT_INFRA_ERROR

    finally:
        try:
            network_log_cleanup()
        except OSError:
            pass
        shutil.rmtree(execution_context_dir, ignore_errors=True)

    return exit_code


def _execute(args: argparse.Namespace, config: _SandboxCliConfig) -> int:
    """Orchestrate sandbox lifecycle and command execution.

    Wraps the async implementation with ``asyncio.run()``.

    Args:
        args: Parsed CLI arguments.
        config: Parsed sandbox configuration.

    Returns:
        Exit code for the CLI process.
    """
    return asyncio.run(_execute_async(args, config))


# -------------------------------------------------------------------
# Signal handling
# -------------------------------------------------------------------


def _install_signal_handlers(task: object) -> None:
    """Forward SIGTERM and SIGINT to the container.

    Args:
        task: CommandTask instance with a ``stop()`` method.
    """
    if not isinstance(task, CommandTask):
        return

    def handler(signum: int, frame: object) -> None:
        logger.info("Received signal %d, stopping task", signum)
        task.stop()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


# -------------------------------------------------------------------
# Exit code mapping
# -------------------------------------------------------------------


def _map_exit_code(result: CommandResult) -> int:
    """Map a ``CommandResult`` to a CLI exit code.

    Args:
        result: Execution result.

    Returns:
        Exit code per spec section 2.7.
    """
    if result.timed_out:
        logger.error("Container execution timed out")
        return EXIT_TIMEOUT

    if result.exit_code == 137:
        logger.warning(
            "Container killed by memory limit (OOM). "
            "Consider increasing resource_limits.memory "
            "in .airut/sandbox.yaml"
        )

    return result.exit_code


# -------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------


def _run(argv: list[str]) -> int:
    """Core CLI logic.

    Args:
        argv: Command-line arguments (without program name).

    Returns:
        Exit code.
    """
    args = _parse_args(argv)

    _setup_logging(
        verbose=getattr(args, "verbose", False),
        debug=getattr(args, "debug", False),
        log_file=getattr(args, "log", None),
    )

    if args.subcommand != "run":
        if args.subcommand is None:
            logger.error("No subcommand specified (use 'run')")
        else:
            logger.error("Unknown subcommand: %s", args.subcommand)
        return EXIT_INFRA_ERROR

    config_path = getattr(args, "config", None) or Path(".airut/sandbox.yaml")
    try:
        config = _load_config(config_path)
    except _ConfigError as e:
        logger.error("Configuration error: %s", e)
        return EXIT_INFRA_ERROR

    return _execute(args, config)


def main() -> None:
    """Entry point for ``airut-sandbox``."""
    sys.exit(_run(sys.argv[1:]))
