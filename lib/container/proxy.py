# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-task proxy lifecycle management for Airut email gateway.

Manages mitmproxy containers that enforce the network sandbox. Each task
gets its own proxy container and internal network, providing complete
network isolation between concurrent tasks.

See ``spec/container/network-sandbox.md`` for the full design.

Lifecycle layers:

- **Gateway**: Egress network, proxy image, CA certificate (shared)
- **Task**: Internal network + proxy container (per-task)
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from lib.git_mirror import GitMirrorCache


logger = logging.getLogger(__name__)

EGRESS_NETWORK = "airut-egress"
PROXY_IMAGE_NAME = "airut-proxy"
PROXY_PORT = 8080
MITMPROXY_CONFDIR = Path.home() / ".airut-mitmproxy"
CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"

# Prefixes for per-task resources.  Orphan cleanup uses prefix-based
# matching via ``podman ps --filter name=`` / ``podman network ls
# --filter name=``.  This is safe in our controlled environment where
# only this code creates resources with these prefixes.
TASK_NETWORK_PREFIX = "airut-task-"
TASK_PROXY_PREFIX = "airut-proxy-"

# Maximum time to wait for the proxy to start accepting connections.
HEALTH_CHECK_TIMEOUT = 5.0
HEALTH_CHECK_INTERVAL = 0.2

# Network sandbox log file name (created in session directory)
NETWORK_LOG_FILENAME = "network-sandbox.log"


@dataclass(frozen=True)
class TaskProxy:
    """Running proxy for a single task.

    Attributes:
        network_name: Per-task internal network name.
        proxy_container_name: Per-task proxy container name.
        proxy_host: Proxy hostname (same as container name, resolved via DNS).
        proxy_port: Proxy listen port (always 8080).
    """

    network_name: str
    proxy_container_name: str
    proxy_host: str
    proxy_port: int = PROXY_PORT


class ProxyError(Exception):
    """Base exception for proxy management errors."""


class ProxyManager:
    """Manages proxy infrastructure lifecycle.

    Gateway-scoped resources (egress network, image, CA cert) are set up
    once in ``startup()`` and torn down in ``shutdown()``.  Task-scoped
    resources (internal network, proxy container) are created per-task via
    ``start_task_proxy()`` and destroyed via ``stop_task_proxy()``.

    Thread Safety:
        ``_active_proxies`` is protected by ``_lock``.  Multiple threads
        may call ``start_task_proxy`` / ``stop_task_proxy`` concurrently.

    Attributes:
        container_command: Container runtime (podman or docker).
        docker_dir: Path to directory containing proxy.dockerfile.
    """

    #: Path to the network allowlist inside the repo.
    ALLOWLIST_PATH = ".airut/network-allowlist.yaml"

    def __init__(
        self,
        container_command: str = "podman",
        docker_dir: Path | None = None,
        egress_network: str = EGRESS_NETWORK,
    ) -> None:
        self._cmd = container_command
        self._docker_dir = docker_dir or Path("docker")
        self._egress_network = egress_network
        self._lock = threading.Lock()
        self._active_proxies: dict[str, TaskProxy] = {}
        self._allowlist_tmpfiles: dict[str, Path] = {}
        self._network_log_files: dict[str, Path] = {}

    # ------------------------------------------------------------------
    # Gateway lifecycle
    # ------------------------------------------------------------------

    def startup(self) -> None:
        """Prepare shared proxy infrastructure.

        1. Clean up orphaned resources from previous unclean shutdown.
        2. Build proxy image.
        3. Ensure CA certificate exists.
        4. Create shared egress network.

        Raises:
            ProxyError: If any setup step fails.
        """
        logger.info("ProxyManager starting up")
        self._cleanup_orphans()
        self._build_image()
        self._ensure_ca_cert()
        self._recreate_network(self._egress_network, internal=False)
        logger.info("ProxyManager startup complete")

    def shutdown(self) -> None:
        """Tear down all proxy resources.

        Stops any remaining task proxies, then removes the egress network.
        """
        logger.info("ProxyManager shutting down")
        # Stop any remaining task proxies
        with self._lock:
            remaining = list(self._active_proxies)
        for task_id in remaining:
            try:
                self.stop_task_proxy(task_id)
            except Exception:
                logger.warning(
                    "Failed to stop proxy for task %s during shutdown",
                    task_id,
                    exc_info=True,
                )
        self._remove_network(self._egress_network)
        logger.info("ProxyManager shutdown complete")

    # ------------------------------------------------------------------
    # Task lifecycle
    # ------------------------------------------------------------------

    def start_task_proxy(
        self,
        task_id: str,
        *,
        mirror: GitMirrorCache,
        session_dir: Path | None = None,
    ) -> TaskProxy:
        """Create internal network and start proxy container for a task.

        Idempotent: if a proxy already exists for *task_id* (e.g. from a
        failed previous attempt), it is torn down first.

        Args:
            task_id: Unique task/conversation identifier.
            mirror: Git mirror to read the network allowlist from.
            session_dir: Optional session directory for network activity log.
                If provided, network requests are logged to
                ``session_dir/network-sandbox.log``.

        Returns:
            TaskProxy with connection details.

        Raises:
            ProxyError: If network/container creation or health check fails.
        """
        # Tear down stale resources from a previous attempt (idempotent).
        self.stop_task_proxy(task_id)

        network_name = f"{TASK_NETWORK_PREFIX}{task_id}"
        container_name = f"{TASK_PROXY_PREFIX}{task_id}"

        logger.info(
            "Starting proxy for task %s (network=%s, container=%s)",
            task_id,
            network_name,
            container_name,
        )

        # Create per-task internal network
        self._create_network(network_name, internal=True)

        # Create network log file if session_dir provided
        network_log_path: Path | None = None
        if session_dir is not None:
            network_log_path = self._create_network_log(task_id, session_dir)

        try:
            # Extract allowlist from git mirror
            allowlist_path = self._extract_allowlist(task_id, mirror=mirror)
            # Start proxy container on both networks
            self._run_proxy_container(
                container_name,
                network_name,
                allowlist_path,
                network_log_path=network_log_path,
            )
            # Wait until mitmdump is accepting connections
            self._wait_for_proxy_ready(container_name)
        except Exception:
            # Clean up network, container, and temp files on any failure
            self._remove_container(container_name)
            self._remove_network(network_name)
            self._cleanup_allowlist(task_id)
            self._cleanup_network_log(task_id)
            raise

        proxy = TaskProxy(
            network_name=network_name,
            proxy_container_name=container_name,
            proxy_host=container_name,
            proxy_port=PROXY_PORT,
        )
        with self._lock:
            self._active_proxies[task_id] = proxy
        logger.info("Proxy started for task %s", task_id)
        return proxy

    def stop_task_proxy(self, task_id: str) -> None:
        """Stop proxy container and remove internal network for a task.

        Safe to call even if the proxy was never started or already stopped.

        Args:
            task_id: Task identifier.
        """
        with self._lock:
            proxy = self._active_proxies.pop(task_id, None)
        if proxy is None:
            logger.debug("No active proxy for task %s", task_id)
            return

        logger.info("Stopping proxy for task %s", task_id)
        self._remove_container(proxy.proxy_container_name)
        self._remove_network(proxy.network_name)
        self._cleanup_allowlist(task_id)
        # Note: we don't delete the network log file - it stays in session_dir
        # for later inspection and is cleaned up with session pruning
        self._network_log_files.pop(task_id, None)
        logger.info("Proxy stopped for task %s", task_id)

    # ------------------------------------------------------------------
    # Image and CA cert
    # ------------------------------------------------------------------

    def _build_image(self) -> None:
        """Build the proxy container image.

        Raises:
            ProxyError: If build fails.
        """
        dockerfile = self._docker_dir / "proxy.dockerfile"
        if not dockerfile.exists():
            raise ProxyError(f"Proxy Dockerfile not found: {dockerfile}")

        logger.info("Building proxy image: %s", PROXY_IMAGE_NAME)
        try:
            subprocess.run(
                [
                    self._cmd,
                    "build",
                    "-t",
                    PROXY_IMAGE_NAME,
                    "-f",
                    str(dockerfile),
                    str(self._docker_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise ProxyError(
                f"Proxy image build failed: {e.stderr.strip()}"
            ) from e
        logger.info("Proxy image built")

    def _ensure_ca_cert(self) -> Path:
        """Ensure mitmproxy CA certificate exists.

        Generates a new certificate by briefly running mitmdump if one does
        not exist.

        Returns:
            Path to the CA certificate PEM file.

        Raises:
            ProxyError: If certificate generation fails.
        """
        ca_cert_path = MITMPROXY_CONFDIR / CA_CERT_FILENAME
        if ca_cert_path.exists():
            logger.debug("CA certificate exists: %s", ca_cert_path)
            return ca_cert_path

        logger.info("Generating mitmproxy CA certificate")
        MITMPROXY_CONFDIR.mkdir(parents=True, exist_ok=True)

        container_confdir = "/tmp/mitmproxy-confdir"
        proc = subprocess.Popen(
            [
                self._cmd,
                "run",
                "--rm",
                "-v",
                f"{MITMPROXY_CONFDIR}:{container_confdir}:rw",
                PROXY_IMAGE_NAME,
                "--set",
                f"confdir={container_confdir}",
                "--listen-port",
                "0",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for _ in range(20):
            if ca_cert_path.exists():
                break
            time.sleep(0.5)

        proc.terminate()
        proc.wait(timeout=10)

        if not ca_cert_path.exists():
            raise ProxyError(
                f"Failed to generate CA certificate at {ca_cert_path}"
            )

        logger.info("CA certificate generated: %s", ca_cert_path)
        return ca_cert_path

    # ------------------------------------------------------------------
    # Container operations
    # ------------------------------------------------------------------

    def _extract_allowlist(
        self, task_id: str, *, mirror: GitMirrorCache
    ) -> Path:
        """Extract the network allowlist from the git mirror to a temp file.

        Args:
            task_id: Task identifier (for tracking cleanup).
            mirror: Git mirror to read the allowlist from.

        Returns:
            Path to the temporary allowlist file.

        Raises:
            ProxyError: If the allowlist cannot be read from the mirror.
        """
        try:
            data = mirror.read_file(self.ALLOWLIST_PATH)
        except Exception as e:
            raise ProxyError(
                f"Failed to read allowlist from mirror: {e}"
            ) from e

        fd, path = tempfile.mkstemp(suffix=".yaml", prefix="airut-allowlist-")
        with open(fd, "wb") as f:
            f.write(data)

        tmppath = Path(path)
        self._allowlist_tmpfiles[task_id] = tmppath
        logger.debug("Extracted allowlist for task %s: %s", task_id, tmppath)
        return tmppath

    def _cleanup_allowlist(self, task_id: str) -> None:
        """Remove the temporary allowlist file for a task."""
        tmppath = self._allowlist_tmpfiles.pop(task_id, None)
        if tmppath is not None:
            tmppath.unlink(missing_ok=True)
            logger.debug(
                "Cleaned up allowlist for task %s: %s", task_id, tmppath
            )

    def _create_network_log(self, task_id: str, session_dir: Path) -> Path:
        """Create the network log file in the session directory.

        Args:
            task_id: Task identifier (for tracking).
            session_dir: Session directory to create log file in.

        Returns:
            Path to the created log file.
        """
        log_path = session_dir / NETWORK_LOG_FILENAME
        # Create empty file (proxy addon will append to it)
        log_path.touch(exist_ok=True)
        self._network_log_files[task_id] = log_path
        logger.debug("Created network log for task %s: %s", task_id, log_path)
        return log_path

    def _cleanup_network_log(self, task_id: str) -> None:
        """Remove tracking for network log file (but keep the file itself)."""
        self._network_log_files.pop(task_id, None)

    def _run_proxy_container(
        self,
        container_name: str,
        internal_network: str,
        allowlist_path: Path,
        *,
        network_log_path: Path | None = None,
    ) -> None:
        """Start a proxy container in detached mode.

        Args:
            container_name: Name for the container.
            internal_network: Per-task internal network name.
            allowlist_path: Path to the allowlist YAML file to mount.
            network_log_path: Optional path to network log file to mount.

        Raises:
            ProxyError: If container start fails.
        """
        allowlist_script = self._docker_dir / "proxy-allowlist.py"

        cmd = [
            self._cmd,
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "--network",
            internal_network,
            "--network",
            self._egress_network,
            "-v",
            f"{MITMPROXY_CONFDIR}:/mitmproxy-confdir:rw",
            "-v",
            f"{allowlist_script}:/proxy-allowlist.py:ro",
            "-v",
            f"{allowlist_path}:/network-allowlist.yaml:ro",
        ]

        # Mount network log file if provided
        if network_log_path is not None:
            cmd.extend(["-v", f"{network_log_path}:/network-sandbox.log:rw"])

        cmd.extend(
            [
                PROXY_IMAGE_NAME,
                "--quiet",
                "--listen-host",
                "0.0.0.0",
                "--listen-port",
                str(PROXY_PORT),
                "--set",
                "confdir=/mitmproxy-confdir",
                "--set",
                "flow_detail=0",
                "-s",
                "/proxy-allowlist.py",
            ]
        )

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ProxyError(
                f"Failed to start proxy container {container_name}: "
                f"{e.stderr.strip()}"
            ) from e

        logger.debug("Proxy container started: %s", container_name)

    def _wait_for_proxy_ready(
        self,
        container_name: str,
        timeout: float = HEALTH_CHECK_TIMEOUT,
    ) -> None:
        """Poll until mitmdump is listening on its port.

        Uses ``podman exec`` to make a TCP connection from inside the
        container.  The proxy image is ``python:3.13-slim``, so Python
        stdlib is available for the probe.

        Args:
            container_name: Running proxy container to check.
            timeout: Maximum seconds to wait.

        Raises:
            ProxyError: If the proxy is not ready within *timeout*.
        """
        deadline = time.monotonic() + timeout
        probe_script = (
            "import socket; "
            f"s = socket.create_connection(('127.0.0.1', {PROXY_PORT}), "
            "timeout=1); s.close()"
        )

        while time.monotonic() < deadline:
            try:
                subprocess.run(
                    [
                        self._cmd,
                        "exec",
                        container_name,
                        "python3",
                        "-c",
                        probe_script,
                    ],
                    check=True,
                    capture_output=True,
                    timeout=3,
                )
                logger.info("Proxy %s is ready", container_name)
                return
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
            ):
                time.sleep(HEALTH_CHECK_INTERVAL)

        raise ProxyError(f"Proxy {container_name} not ready after {timeout}s")

    def _remove_container(self, name: str) -> None:
        """Force-remove a container (idempotent).

        Args:
            name: Container name.
        """
        try:
            subprocess.run(
                [self._cmd, "rm", "-f", name],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.debug("Removed container: %s", name)
        except subprocess.CalledProcessError:
            logger.debug("Container already gone: %s", name)

    # ------------------------------------------------------------------
    # Network operations
    # ------------------------------------------------------------------

    def _create_network(self, name: str, *, internal: bool) -> None:
        """Create a Podman network.

        Args:
            name: Network name.
            internal: If True, create with --internal (no internet).

        Raises:
            ProxyError: If creation fails.
        """
        cmd = [self._cmd, "network", "create"]
        if internal:
            cmd.append("--internal")
        cmd.append(name)

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ProxyError(
                f"Failed to create network {name}: {e.stderr.strip()}"
            ) from e
        logger.debug("Created network: %s (internal=%s)", name, internal)

    def _recreate_network(self, name: str, *, internal: bool) -> None:
        """Remove and recreate a network (idempotent).

        Args:
            name: Network name.
            internal: If True, create with --internal.
        """
        self._remove_network(name)
        self._create_network(name, internal=internal)

    def _remove_network(self, name: str) -> None:
        """Force-remove a network (idempotent).

        Args:
            name: Network name.
        """
        try:
            subprocess.run(
                [self._cmd, "network", "rm", "-f", name],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.debug("Removed network: %s", name)
        except subprocess.CalledProcessError:
            logger.debug("Network already gone or not found: %s", name)

    # ------------------------------------------------------------------
    # Orphan cleanup
    # ------------------------------------------------------------------

    def _cleanup_orphans(self) -> None:
        """Remove orphaned proxy containers and task networks.

        Finds resources matching the ``airut-proxy-*`` and
        ``airut-task-*`` naming patterns from previous unclean shutdowns
        and removes them.
        """
        # Clean orphaned containers
        try:
            result = subprocess.run(
                [
                    self._cmd,
                    "ps",
                    "-a",
                    "--filter",
                    f"name={TASK_PROXY_PREFIX}",
                    "--format",
                    "{{.Names}}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            for name in result.stdout.strip().splitlines():
                name = name.strip()
                if name:
                    logger.info("Removing orphaned proxy container: %s", name)
                    self._remove_container(name)
        except subprocess.CalledProcessError:
            logger.debug("Failed to list orphaned containers")

        # Clean orphaned networks
        try:
            result = subprocess.run(
                [
                    self._cmd,
                    "network",
                    "ls",
                    "--filter",
                    f"name={TASK_NETWORK_PREFIX}",
                    "--format",
                    "{{.Name}}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            for name in result.stdout.strip().splitlines():
                name = name.strip()
                if name:
                    logger.info("Removing orphaned task network: %s", name)
                    self._remove_network(name)
        except subprocess.CalledProcessError:
            logger.debug("Failed to list orphaned networks")


def get_ca_cert_path() -> Path:
    """Get path to the mitmproxy CA certificate.

    Returns:
        Path to CA certificate PEM file.

    Raises:
        RuntimeError: If certificate doesn't exist.
    """
    path = MITMPROXY_CONFDIR / CA_CERT_FILENAME
    if not path.exists():
        raise RuntimeError(
            f"CA certificate not found: {path}. "
            "ProxyManager.startup() must be called first."
        )
    return path
