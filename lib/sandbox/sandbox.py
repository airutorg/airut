# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Top-level sandbox manager.

Manages shared infrastructure (proxy image, CA cert, egress network)
and creates Task instances for individual executions.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

from lib.sandbox._image import (
    _ImageInfo,
    build_overlay_image,
    build_repo_image,
)
from lib.sandbox._proxy import ProxyManager
from lib.sandbox.task import ContainerEnv, Mount, NetworkSandboxConfig, Task


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SandboxConfig:
    """Construction-time configuration for the sandbox.

    Attributes:
        container_command: Container runtime command (podman or docker).
        proxy_dir: Path to directory containing proxy.dockerfile.
        upstream_dns: Upstream DNS server for the proxy.
        max_image_age_hours: Maximum image age before rebuild.
    """

    container_command: str = "podman"
    proxy_dir: Path = field(default_factory=lambda: Path("proxy"))
    upstream_dns: str = "1.1.1.1"
    max_image_age_hours: int = 24


class Sandbox:
    """Top-level sandbox manager.

    Manages shared infrastructure (proxy image, CA cert, egress network)
    and creates Task instances for individual executions.

    Thread Safety: Thread-safe. Multiple threads may call create_task()
    and ensure_image() concurrently. Image builds are serialized.
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

        # Image caches
        self._build_lock = threading.Lock()
        self._repo_images: dict[str, _ImageInfo] = {}
        self._overlay_images: dict[str, _ImageInfo] = {}

        # Proxy manager
        if egress_network is not None:
            self._proxy_manager = ProxyManager(
                container_command=config.container_command,
                proxy_dir=config.proxy_dir,
                egress_network=egress_network,
                upstream_dns=config.upstream_dns,
            )
        else:
            self._proxy_manager = ProxyManager(
                container_command=config.container_command,
                proxy_dir=config.proxy_dir,
                upstream_dns=config.upstream_dns,
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

    def ensure_image(
        self,
        dockerfile: bytes,
        context_files: dict[str, bytes],
    ) -> str:
        """Build or reuse two-layer container image.

        Builds the repo image from the provided Dockerfile and context
        files, then builds the overlay with the generated entrypoint.
        Images are cached by content hash with staleness checking.

        Args:
            dockerfile: Raw Dockerfile content.
            context_files: Additional files for build context.

        Returns:
            Image tag for use in create_task().

        Raises:
            ImageBuildError: If image build fails.
        """
        with self._build_lock:
            repo_tag = build_repo_image(
                self._container_command,
                dockerfile,
                context_files,
                self._repo_images,
                self._config.max_image_age_hours,
            )

            overlay_tag = build_overlay_image(
                self._container_command,
                repo_tag,
                self._overlay_images,
                self._config.max_image_age_hours,
            )

            return overlay_tag

    def create_task(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        session_dir: Path,
        network_log_dir: Path | None = None,
        network_sandbox: NetworkSandboxConfig | None = None,
        timeout_seconds: int = 300,
    ) -> Task:
        """Create a task for sandboxed execution.

        The sandbox owns:
        - session_dir/context.json -- session metadata and history
        - session_dir/claude/ -- Claude session state directory
          (mounted at /root/.claude in the container)
        - network_log_dir/network-sandbox.log -- network activity log
          (if network_log_dir provided)

        The claude/ subdirectory is created automatically and mounted
        by the sandbox. It must not appear in the caller's mounts list.

        Does not start execution -- call task.execute() to run.

        Args:
            execution_context_id: Execution context identifier — an
                opaque string used to scope session state, network
                resources, and container naming.
            image_tag: Container image tag (from ensure_image()).
            mounts: Volume mounts for the container.
            env: Container environment variables.
            session_dir: Directory for session state.
            network_log_dir: Directory for network activity log.
            network_sandbox: Network sandbox configuration.
            timeout_seconds: Maximum execution time.

        Returns:
            Task instance ready for execution.
        """
        return Task(
            execution_context_id,
            image_tag=image_tag,
            mounts=mounts,
            env=env,
            session_dir=session_dir,
            network_log_dir=network_log_dir,
            network_sandbox=network_sandbox,
            timeout_seconds=timeout_seconds,
            container_command=self._container_command,
            proxy_manager=(
                self._proxy_manager if network_sandbox is not None else None
            ),
        )
