# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Top-level sandbox manager.

Manages shared infrastructure (proxy image, CA cert, egress network)
and creates AgentTask and CommandTask instances for individual
executions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from airut.sandbox._entrypoint import get_entrypoint_content
from airut.sandbox._image_cache import ImageBuildSpec, ImageCache
from airut.sandbox._proxy import ProxyManager
from airut.sandbox.task import (
    AgentTask,
    CommandTask,
    ContainerEnv,
    Mount,
    NetworkSandboxConfig,
)
from airut.sandbox.types import ResourceLimits


logger = logging.getLogger(__name__)


def default_proxy_dir() -> Path:
    """Resolve the proxy directory from embedded package data."""
    return Path(str(files("airut._bundled.proxy")))


@dataclass(frozen=True)
class SandboxConfig:
    """Construction-time configuration for the sandbox.

    Attributes:
        container_command: Container runtime command (podman or docker).
        proxy_dir: Path to directory containing proxy.dockerfile.
        upstream_dns: Upstream DNS server for the proxy.
        max_image_age_hours: Maximum image age before rebuild.
        resource_prefix: Prefix for container/network resources.
            Different prefixes isolate sandbox instances running on the
            same host (e.g. ``"airut"`` for the gateway, ``"airut-cli"``
            for the standalone CLI).
    """

    container_command: str = "podman"
    proxy_dir: Path = field(default_factory=default_proxy_dir)
    upstream_dns: str = "1.1.1.1"
    max_image_age_hours: int = 24
    resource_prefix: str = "airut"


class Sandbox:
    """Top-level sandbox manager.

    Manages shared infrastructure (proxy image, CA cert, egress network)
    and creates AgentTask/CommandTask instances for individual executions.

    Thread Safety: Thread-safe. Multiple threads may call create_task()
    and ensure_image() concurrently. Image builds are serialized via
    ImageCache.
    """

    def __init__(
        self,
        config: SandboxConfig,
        *,
        egress_network: str | None = None,
    ) -> None:
        """Initialize sandbox.

        Args:
            config: Sandbox configuration.
            egress_network: Override for proxy egress network name.
        """
        self._config = config
        self._container_command = config.container_command

        # Unified image cache for all image types
        self._image_cache = ImageCache(
            container_command=config.container_command,
            resource_prefix=config.resource_prefix,
            max_age_hours=config.max_image_age_hours,
        )

        # Proxy manager with injected image cache
        self._proxy_manager = ProxyManager(
            container_command=config.container_command,
            proxy_dir=config.proxy_dir,
            egress_network=egress_network,
            upstream_dns=config.upstream_dns,
            resource_prefix=config.resource_prefix,
            image_cache=self._image_cache,
        )

    @property
    def proxy_manager(self) -> ProxyManager:
        """Access the proxy manager (for gateway integration)."""
        return self._proxy_manager

    def startup(self) -> None:
        """Prepare shared infrastructure.

        1. Clean orphaned resources from previous unclean shutdown.
        2. Build proxy container image.
        3. Ensure CA certificate exists.
        4. Create shared egress network.

        Must be called before create_task().

        Raises:
            SandboxError: If any setup step fails.
        """
        logger.info("Sandbox starting up")
        self._proxy_manager.startup()
        logger.info("Sandbox startup complete")

    def shutdown(self) -> None:
        """Tear down all infrastructure. Stops any active tasks."""
        logger.info("Sandbox shutting down")
        self._proxy_manager.shutdown()
        logger.info("Sandbox shutdown complete")

    def prune_images(self) -> int:
        """Prune dangling and stale container images.

        Delegates to :meth:`ImageCache.prune_images`.  Does not hold the
        image build lock, so concurrent ``ensure_image()`` calls are not
        blocked.

        Returns:
            Number of old prefixed images removed.
        """
        return self._image_cache.prune_images()

    def ensure_image(
        self,
        dockerfile: bytes,
        context_files: dict[str, bytes],
        *,
        passthrough_entrypoint: bool = False,
    ) -> str:
        """Build or reuse two-layer container image.

        Builds the repo image from the provided Dockerfile and context
        files, then builds the overlay with the generated entrypoint.
        Images are cached by content hash with staleness checking.

        Args:
            dockerfile: Raw Dockerfile content.
            context_files: Additional files for build context.
            passthrough_entrypoint: If True, use the passthrough
                entrypoint (``exec "$@"``) instead of the Claude
                entrypoint (``exec claude "$@"``).

        Returns:
            Image tag for use in create_task() or create_command_task().

        Raises:
            ImageBuildError: If image build fails.
        """
        repo_spec = ImageBuildSpec(
            kind="repo",
            dockerfile=dockerfile,
            context_files=context_files,
        )

        # Detect whether repo was rebuilt (for force-cascading to overlay).
        repo_tag = self._image_cache.tag_for(repo_spec)
        repo_created_before = self._image_cache.get_image_created(repo_tag)
        repo_tag = self._image_cache.ensure(repo_spec)
        repo_rebuilt = (
            repo_created_before is None
            or self._image_cache.get_image_created(repo_tag)
            != repo_created_before
        )

        entrypoint = get_entrypoint_content(
            passthrough=passthrough_entrypoint,
        )
        overlay_df = (
            f"FROM {repo_tag}\n"
            f"COPY airut-entrypoint.sh /entrypoint.sh\n"
            f"RUN chmod +x /entrypoint.sh\n"
            f'ENTRYPOINT ["/entrypoint.sh"]\n'
        ).encode()
        overlay_spec = ImageBuildSpec(
            kind="overlay",
            dockerfile=overlay_df,
            context_files={"airut-entrypoint.sh": entrypoint},
        )
        overlay_tag = self._image_cache.ensure(
            overlay_spec,
            force=repo_rebuilt,
        )

        return overlay_tag

    def create_task(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        execution_context_dir: Path,
        network_log_path: Path | None = None,
        network_sandbox: NetworkSandboxConfig | None = None,
        resource_limits: ResourceLimits | None = None,
        claude_binary_path: Path | None = None,
    ) -> AgentTask:
        """Create a task for sandboxed Claude Code execution.

        The sandbox owns:
        - execution_context_dir/events.jsonl -- append-only event log
        - execution_context_dir/claude/ -- Claude session state directory
          (mounted at /root/.claude in the container)
        - network_log_path -- network activity log
          (if network_log_path provided)

        The claude/ subdirectory is created automatically and mounted
        by the sandbox. It must not appear in the caller's mounts list.

        Does not start execution -- call task.execute() to run.

        Args:
            execution_context_id: Execution context identifier -- an
                opaque string used to scope execution context state,
                network resources, and container naming.
            image_tag: Container image tag (from ensure_image()).
            mounts: Volume mounts for the container.
            env: Container environment variables.
            execution_context_dir: Directory for execution context state.
            network_log_path: File path for network activity log.
            network_sandbox: Network sandbox configuration.
            resource_limits: Container resource limits (timeout, memory,
                cpus, pids_limit).
            claude_binary_path: Host path to cached Claude binary.
                When provided, the binary is bind-mounted read-only at
                ``/opt/claude/claude`` in the container.

        Returns:
            AgentTask instance ready for execution.
        """
        return AgentTask(
            execution_context_id,
            image_tag=image_tag,
            mounts=mounts,
            env=env,
            execution_context_dir=execution_context_dir,
            network_log_path=network_log_path,
            network_sandbox=network_sandbox,
            resource_limits=resource_limits or ResourceLimits(),
            container_command=self._container_command,
            proxy_manager=(
                self._proxy_manager if network_sandbox is not None else None
            ),
            claude_binary_path=claude_binary_path,
        )

    def create_command_task(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        execution_context_dir: Path,
        network_log_path: Path | None = None,
        network_sandbox: NetworkSandboxConfig | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> CommandTask:
        """Create a task for sandboxed generic command execution.

        Unlike ``create_task()``, the returned ``CommandTask`` does not
        create a Claude session directory or event log. It runs an
        arbitrary command in the same sandboxed container environment.

        Args:
            execution_context_id: Execution context identifier.
            image_tag: Container image tag (from ensure_image()).
            mounts: Volume mounts for the container.
            env: Container environment variables.
            execution_context_dir: Directory for execution context state.
            network_log_path: File path for network activity log.
            network_sandbox: Network sandbox configuration.
            resource_limits: Container resource limits.

        Returns:
            CommandTask instance ready for execution.
        """
        return CommandTask(
            execution_context_id,
            image_tag=image_tag,
            mounts=mounts,
            env=env,
            execution_context_dir=execution_context_dir,
            network_log_path=network_log_path,
            network_sandbox=network_sandbox,
            resource_limits=resource_limits or ResourceLimits(),
            container_command=self._container_command,
            proxy_manager=(
                self._proxy_manager if network_sandbox is not None else None
            ),
        )
