# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-conversation proxy lifecycle management for Airut email gateway.

Manages mitmproxy containers that enforce the network sandbox. Each
conversation gets its own proxy container and internal network, providing
complete network isolation between concurrent conversations.

Architecture (transparent DNS-spoofing proxy):

- A custom DNS responder in the proxy container returns the proxy IP
  for all allowed domains and NXDOMAIN for blocked domains.
- The client container's default route points to the proxy IP via
  Podman's ``--route`` flag on the internal network.
- mitmproxy in ``regular`` mode uses SNI (HTTPS) and Host header (HTTP)
  to determine the real upstream destination.
- No ``HTTP_PROXY`` / ``HTTPS_PROXY`` env vars needed — transparent to
  all tools (Node.js, Go, curl, etc.).
- No ``CAP_NET_ADMIN``, no iptables, no ip_forward.

Lifecycle layers:

- **Gateway**: Egress network, proxy image, CA certificate (shared)
- **Conversation**: Internal network + proxy container (per-conversation)

See ``doc/network-sandbox.md`` for the full design.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from lib.gateway.config import ReplacementMap
    from lib.git_mirror import GitMirrorCache


logger = logging.getLogger(__name__)

EGRESS_NETWORK = "airut-egress"
PROXY_IMAGE_NAME = "airut-proxy"
MITMPROXY_CONFDIR = Path.home() / ".airut-mitmproxy"
CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"

# Prefixes for per-conversation resources.  Orphan cleanup uses prefix-based
# matching via ``podman ps --filter name=`` / ``podman network ls
# --filter name=``.  This is safe in our controlled environment where
# only this code creates resources with these prefixes.
CONV_NETWORK_PREFIX = "airut-conv-"
CONV_PROXY_PREFIX = "airut-proxy-"

# Maximum time to wait for the proxy to start accepting connections.
HEALTH_CHECK_TIMEOUT = 5.0
HEALTH_CHECK_INTERVAL = 0.2

# Network sandbox log file name (created in conversation directory)
NETWORK_LOG_FILENAME = "network-sandbox.log"

# Subnet allocation for per-conversation internal networks.
# Each conversation gets a /24 subnet from 10.199.{N}.0/24.
# Proxy IP is always .100 on the subnet.
_SUBNET_PREFIX = "10.199"
_PROXY_HOST_OCTET = "100"
_SUBNET_MASK = "/24"

# Route metrics: egress must have lower metric than internal so the
# proxy container's internet access uses the egress network.
_EGRESS_METRIC = 5
_INTERNAL_ROUTE_METRIC = 10


@dataclass(frozen=True)
class TaskProxy:
    """Running proxy for a single task.

    Attributes:
        network_name: Per-task internal network name.
        proxy_container_name: Per-task proxy container name.
        proxy_ip: Static IP of the proxy on the internal network.
    """

    network_name: str
    proxy_container_name: str
    proxy_ip: str


class ProxyError(Exception):
    """Base exception for proxy management errors."""


class ProxyManager:
    """Manages proxy infrastructure lifecycle.

    Gateway-scoped resources (egress network, image, CA cert) are set up
    once in ``startup()`` and torn down in ``shutdown()``.
    Conversation-scoped resources (internal network, proxy container) are
    created per-conversation via ``start_task_proxy()`` and destroyed via
    ``stop_task_proxy()``.

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
        *,
        upstream_dns: str,
    ) -> None:
        self._cmd = container_command
        self._docker_dir = docker_dir or Path("docker")
        self._egress_network = egress_network
        self._upstream_dns = upstream_dns
        self._lock = threading.Lock()
        self._active_proxies: dict[str, TaskProxy] = {}
        self._allowlist_tmpfiles: dict[str, Path] = {}
        self._replacement_tmpfiles: dict[str, Path] = {}
        self._network_log_files: dict[str, Path] = {}
        # Subnet allocator: next third-octet to try.
        self._next_subnet_octet = 1

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
        self._recreate_egress_network()
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
        conversation_dir: Path | None = None,
        replacement_map: ReplacementMap | None = None,
    ) -> TaskProxy:
        """Create internal network and start proxy container for a task.

        Idempotent: if a proxy already exists for *task_id* (e.g. from a
        failed previous attempt), it is torn down first.

        Args:
            task_id: Unique task/conversation identifier.
            mirror: Git mirror to read the network allowlist from.
            conversation_dir: Optional conversation directory for network
                activity log. If provided, network requests are logged to
                ``conversation_dir/network-sandbox.log``.
            replacement_map: Optional mapping of surrogate tokens to real
                values with scope restrictions. Used for masked secrets.

        Returns:
            TaskProxy with connection details.

        Raises:
            ProxyError: If network/container creation or health check fails.
        """
        # Tear down stale resources from a previous attempt (idempotent).
        self.stop_task_proxy(task_id)

        network_name = f"{CONV_NETWORK_PREFIX}{task_id}"
        container_name = f"{CONV_PROXY_PREFIX}{task_id}"

        logger.info(
            "Starting proxy for task %s (network=%s, container=%s)",
            task_id,
            network_name,
            container_name,
        )

        # Allocate subnet and create internal network with route to proxy
        subnet, proxy_ip = self._allocate_subnet()
        self._create_internal_network(
            network_name, subnet=subnet, proxy_ip=proxy_ip
        )

        # Create network log file if conversation_dir provided
        network_log_path: Path | None = None
        if conversation_dir is not None:
            network_log_path = self._create_network_log(
                task_id, conversation_dir
            )

        try:
            # Extract allowlist from git mirror
            allowlist_path = self._extract_allowlist(task_id, mirror=mirror)
            # Write replacement map for masked secrets
            replacement_path = self._write_replacement_map(
                task_id, replacement_map or {}
            )
            # Start proxy container on both networks
            self._run_proxy_container(
                container_name,
                network_name,
                proxy_ip,
                allowlist_path,
                network_log_path=network_log_path,
                replacement_path=replacement_path,
            )
            # Wait until mitmproxy is accepting connections
            self._wait_for_proxy_ready(container_name)
        except Exception:
            # Clean up network, container, and temp files on any failure
            self._remove_container(container_name)
            self._remove_network(network_name)
            self._cleanup_allowlist(task_id)
            self._cleanup_replacement_map(task_id)
            self._cleanup_network_log(task_id)
            raise

        proxy = TaskProxy(
            network_name=network_name,
            proxy_container_name=container_name,
            proxy_ip=proxy_ip,
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
        self._cleanup_replacement_map(task_id)
        # Note: we don't delete the network log file - it stays in
        # conversation_dir for later inspection and is cleaned up with
        # conversation pruning
        self._network_log_files.pop(task_id, None)
        logger.info("Proxy stopped for task %s", task_id)

    # ------------------------------------------------------------------
    # Subnet allocation
    # ------------------------------------------------------------------

    def _allocate_subnet(self) -> tuple[str, str]:
        """Allocate a /24 subnet and proxy IP for a new task network.

        Uses a simple incrementing counter for the third octet. Podman
        will reject the network creation if the subnet collides with an
        existing one, which is handled by the caller.

        Returns:
            Tuple of (subnet_cidr, proxy_ip).
        """
        with self._lock:
            octet = self._next_subnet_octet
            self._next_subnet_octet = (octet % 254) + 1
        subnet = f"{_SUBNET_PREFIX}.{octet}.0{_SUBNET_MASK}"
        proxy_ip = f"{_SUBNET_PREFIX}.{octet}.{_PROXY_HOST_OCTET}"
        return subnet, proxy_ip

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
        not exist.  The image entrypoint is overridden since the production
        image uses ``proxy-entrypoint.sh``.

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
                "--entrypoint",
                "bash",
                "-v",
                f"{MITMPROXY_CONFDIR}:{container_confdir}:rw",
                PROXY_IMAGE_NAME,
                "-c",
                f"mitmdump --set confdir={container_confdir} "
                "--listen-port 0 & sleep 3; kill $!",
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

    def _write_replacement_map(
        self,
        task_id: str,
        replacement_map: ReplacementMap,
    ) -> Path:
        """Write replacement map to temp file for proxy mounting.

        Args:
            task_id: Task identifier (for tracking cleanup).
            replacement_map: Mapping of surrogate tokens to replacement config.

        Returns:
            Path to the temporary JSON file.
        """
        # Serialize to JSON format expected by proxy addon
        data = {
            surrogate: entry.to_dict()
            for surrogate, entry in replacement_map.items()
        }

        fd, path = tempfile.mkstemp(
            suffix=".json", prefix="airut-replacements-"
        )
        with open(fd, "w") as f:
            json.dump(data, f)

        tmppath = Path(path)
        self._replacement_tmpfiles[task_id] = tmppath
        logger.debug(
            "Wrote replacement map for task %s: %s (%d entries)",
            task_id,
            tmppath,
            len(replacement_map),
        )
        return tmppath

    def _cleanup_replacement_map(self, task_id: str) -> None:
        """Remove the temporary replacement map file for a task."""
        tmppath = self._replacement_tmpfiles.pop(task_id, None)
        if tmppath is not None:
            tmppath.unlink(missing_ok=True)
            logger.debug(
                "Cleaned up replacement map for task %s: %s", task_id, tmppath
            )

    def _create_network_log(self, task_id: str, conversation_dir: Path) -> Path:
        """Create the network log file in the conversation directory.

        Args:
            task_id: Task identifier (for tracking).
            conversation_dir: Conversation directory to create log file in.

        Returns:
            Path to the created log file.
        """
        log_path = conversation_dir / NETWORK_LOG_FILENAME
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
        proxy_ip: str,
        allowlist_path: Path,
        *,
        network_log_path: Path | None = None,
        replacement_path: Path | None = None,
    ) -> None:
        """Start a proxy container in detached mode.

        The proxy is dual-homed: connected to the internal network (with a
        static IP) and the egress network (for internet access).

        Args:
            container_name: Name for the container.
            internal_network: Per-task internal network name.
            proxy_ip: Static IP address on the internal network.
            allowlist_path: Path to the allowlist YAML file to mount.
            network_log_path: Optional path to network log file to mount.
            replacement_path: Optional path to replacement map JSON file.

        Raises:
            ProxyError: If container start fails.
        """
        cmd = [
            self._cmd,
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            # Dual-homed: egress for internet, internal with static IP
            "--network",
            self._egress_network,
            "--network",
            f"{internal_network}:ip={proxy_ip}",
            # Environment
            "-e",
            f"PROXY_IP={proxy_ip}",
            "-e",
            f"UPSTREAM_DNS={self._upstream_dns}",
            # Volume mounts: only per-task config and mutable state
            "-v",
            f"{MITMPROXY_CONFDIR}:/mitmproxy-confdir:rw",
            "-v",
            f"{allowlist_path}:/network-allowlist.yaml:ro",
        ]

        # Mount replacement map if provided
        if replacement_path is not None:
            cmd.extend(["-v", f"{replacement_path}:/replacements.json:ro"])

        # Mount network log file if provided
        if network_log_path is not None:
            cmd.extend(["-v", f"{network_log_path}:/network-sandbox.log:rw"])

        cmd.append(PROXY_IMAGE_NAME)

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
        """Poll until mitmproxy is listening on ports 80 and 443.

        Uses ``podman exec`` to make TCP connections from inside the
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
            "socket.create_connection(('127.0.0.1', 80), timeout=1).close(); "
            "socket.create_connection(('127.0.0.1', 443), timeout=1).close()"
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

    def _create_internal_network(
        self,
        name: str,
        *,
        subnet: str,
        proxy_ip: str,
    ) -> None:
        """Create a per-task internal network with route to proxy.

        Creates an ``--internal`` network with ``--disable-dns`` and a
        default route pointing to the proxy IP. The ``--disable-dns``
        flag prevents aardvark-dns from overriding the client's
        ``--dns`` setting.

        Args:
            name: Network name.
            subnet: CIDR subnet (e.g., "10.199.1.0/24").
            proxy_ip: Proxy IP on this subnet (route target).

        Raises:
            ProxyError: If creation fails.
        """
        cmd = [
            self._cmd,
            "network",
            "create",
            "--internal",
            "--disable-dns",
            "--subnet",
            subnet,
            "--route",
            f"0.0.0.0/0,{proxy_ip},{_INTERNAL_ROUTE_METRIC}",
            name,
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ProxyError(
                f"Failed to create internal network {name}: {e.stderr.strip()}"
            ) from e
        logger.debug(
            "Created internal network: %s (subnet=%s, route->%s)",
            name,
            subnet,
            proxy_ip,
        )

    def _create_egress_network(self) -> None:
        """Create the shared egress network with a low route metric.

        The egress network uses ``metric={_EGRESS_METRIC}`` so its
        default route wins over the internal network's route
        (``metric={_INTERNAL_ROUTE_METRIC}``) inside dual-homed proxy
        containers.

        Raises:
            ProxyError: If creation fails.
        """
        cmd = [
            self._cmd,
            "network",
            "create",
            "-o",
            f"metric={_EGRESS_METRIC}",
            self._egress_network,
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ProxyError(
                f"Failed to create egress network: {e.stderr.strip()}"
            ) from e
        logger.debug(
            "Created egress network: %s (metric=%d)",
            self._egress_network,
            _EGRESS_METRIC,
        )

    def _recreate_egress_network(self) -> None:
        """Remove and recreate the egress network (idempotent)."""
        self._remove_network(self._egress_network)
        self._create_egress_network()

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
        """Remove orphaned proxy containers and conversation networks.

        Finds resources matching the ``airut-proxy-*`` and
        ``airut-conv-*`` naming patterns from previous unclean shutdowns
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
                    f"name={CONV_PROXY_PREFIX}",
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
                    f"name={CONV_NETWORK_PREFIX}",
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
