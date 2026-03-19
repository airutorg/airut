# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-context proxy lifecycle management for the sandbox.

Manages mitmproxy containers that enforce the network sandbox. Each
execution context gets its own proxy container and internal network,
providing complete network isolation between concurrent contexts.

Architecture (transparent DNS-spoofing proxy):

- A custom DNS responder in the proxy container returns the proxy IP
  for all allowed domains and NXDOMAIN for blocked domains.
- The client container's default route points to the proxy IP via
  Podman's ``--route`` flag on the internal network.
- mitmproxy in ``regular`` mode uses SNI (HTTPS) and Host header (HTTP)
  to determine the real upstream destination.
- No ``HTTP_PROXY`` / ``HTTPS_PROXY`` env vars needed -- transparent to
  all tools (Node.js, Go, curl, etc.).
- No ``CAP_NET_ADMIN``, no iptables, no ip_forward.

Lifecycle layers:

- **Sandbox**: Egress network, proxy image, CA certificate (shared)
- **Context**: Internal network + proxy container (per-context)
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from airut.sandbox._image_cache import ImageBuildSpec, ImageCache


logger = logging.getLogger(__name__)

DEFAULT_RESOURCE_PREFIX = "airut"
MITMPROXY_CONFDIR = Path.home() / ".airut-mitmproxy"
CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"

# Maximum time to wait for the proxy to start accepting connections.
HEALTH_CHECK_TIMEOUT = 5.0
HEALTH_CHECK_INTERVAL = 0.2

# Subnet allocation for per-context internal networks.
# Each context gets a /24 subnet from 10.199.{N}.0/24.
# Proxy IP is always .100 on the subnet.
_SUBNET_PREFIX = "10.199"
_PROXY_HOST_OCTET = "100"
_SUBNET_MASK = "/24"

# Route metrics: egress must have lower metric than internal so the
# proxy container's internet access uses the egress network.
_EGRESS_METRIC = 5
_INTERNAL_ROUTE_METRIC = 10


def build_proxy_spec(proxy_dir: Path) -> ImageBuildSpec:
    """Construct ImageBuildSpec for the proxy image.

    Args:
        proxy_dir: Directory containing ``proxy.dockerfile`` and
            supporting files.

    Returns:
        ImageBuildSpec for the proxy image.

    Raises:
        ProxyError: If proxy Dockerfile is missing.
    """
    dockerfile_path = proxy_dir / "proxy.dockerfile"
    if not dockerfile_path.exists():
        raise ProxyError(f"Proxy Dockerfile not found: {dockerfile_path}")

    dockerfile = dockerfile_path.read_bytes()
    context_files: dict[str, bytes] = {}
    for child in sorted(proxy_dir.iterdir()):
        if child.is_file() and child.name != "proxy.dockerfile":
            context_files[child.name] = child.read_bytes()
    return ImageBuildSpec(
        kind="proxy",
        dockerfile=dockerfile,
        context_files=context_files,
    )


@dataclass(frozen=True)
class _ContextProxy:
    """Running proxy for a single execution context.

    Attributes:
        network_name: Per-context internal network name.
        proxy_container_name: Per-context proxy container name.
        proxy_ip: Static IP of the proxy on the internal network.
        subnet_octet: Third octet of the allocated /24 subnet.
    """

    network_name: str
    proxy_container_name: str
    proxy_ip: str
    subnet_octet: int


class ProxyError(Exception):
    """Base exception for proxy management errors."""


class ProxyManager:
    """Manages proxy infrastructure lifecycle.

    Sandbox-scoped resources (egress network, image, CA cert) are set up
    once in ``startup()`` and torn down in ``shutdown()``.
    Context-scoped resources (internal network, proxy container) are
    created per-context via ``start_proxy()`` and destroyed via
    ``stop_proxy()``.

    Thread Safety:
        ``_active_proxies`` and the subnet allocator (``_active_octets``,
        ``_next_subnet_octet``) are protected by ``_lock``.  Multiple
        threads may call ``start_proxy`` / ``stop_proxy`` concurrently.

        The temp-file tracking dicts (``_allowlist_tmpfiles``,
        ``_replacement_tmpfiles``, ``_network_log_files``) are **not**
        locked.  This is safe because each ``context_id`` key is owned
        by exactly one thread at a time (the thread running
        ``start_proxy`` / ``stop_proxy`` for that context), and CPython's
        GIL makes individual ``dict.__setitem__`` / ``dict.pop`` atomic.

        Note: this assumption breaks under free-threaded Python (PEP 703,
        ``python3.13t``).  If free-threaded builds become a target, these
        dicts must be protected by ``_lock`` or a per-key lock.
    """

    def __init__(
        self,
        container_command: str = "podman",
        proxy_dir: Path | None = None,
        egress_network: str | None = None,
        *,
        upstream_dns: str,
        resource_prefix: str = DEFAULT_RESOURCE_PREFIX,
        image_cache: ImageCache,
    ) -> None:
        self._cmd = container_command
        self._proxy_dir = proxy_dir or Path(str(files("airut._bundled.proxy")))
        self._image_cache = image_cache
        self._proxy_image_tag: str | None = None
        self._resource_prefix = resource_prefix
        self._context_network_prefix = f"{resource_prefix}-conv-"
        self._context_proxy_prefix = f"{resource_prefix}-proxy-"
        self._egress_network = (
            egress_network
            if egress_network is not None
            else f"{resource_prefix}-egress"
        )
        self._upstream_dns = upstream_dns
        self._lock = threading.Lock()
        self._active_proxies: dict[str, _ContextProxy] = {}
        self._allowlist_tmpfiles: dict[str, Path] = {}
        self._replacement_tmpfiles: dict[str, Path] = {}
        self._network_log_files: dict[str, Path] = {}
        # Subnet allocator: next third-octet to try, and set of
        # octets currently in use by active proxies.
        self._next_subnet_octet = 1
        self._active_octets: set[int] = set()

    # ------------------------------------------------------------------
    # Sandbox lifecycle
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
        self._ensure_proxy_image()
        self._ensure_ca_cert()
        self._recreate_egress_network()
        logger.info("ProxyManager startup complete")

    def shutdown(self) -> None:
        """Tear down all proxy resources.

        Stops any remaining context proxies, then removes the egress
        network.
        """
        logger.info("ProxyManager shutting down")
        # Stop any remaining context proxies
        with self._lock:
            remaining = list(self._active_proxies)
        for context_id in remaining:
            try:
                self.stop_proxy(context_id)
            except Exception:
                logger.warning(
                    "Failed to stop proxy for context %s during shutdown",
                    context_id,
                    exc_info=True,
                )
        self._remove_network(self._egress_network)
        logger.info("ProxyManager shutdown complete")

    # ------------------------------------------------------------------
    # Context lifecycle
    # ------------------------------------------------------------------

    def start_proxy(
        self,
        context_id: str,
        *,
        allowlist_json: bytes,
        replacements_json: bytes,
        network_log_path: Path | None = None,
    ) -> _ContextProxy:
        """Create internal network and start proxy container for a context.

        Idempotent: if a proxy already exists for *context_id* (e.g.
        from a failed previous attempt), it is torn down first.

        Args:
            context_id: Execution context identifier.
            allowlist_json: JSON-encoded network allowlist.
            replacements_json: JSON-encoded replacement map for secrets.
            network_log_path: Optional file path for network activity log.

        Returns:
            _ContextProxy with connection details.

        Raises:
            ProxyError: If network/container creation or health check fails.
        """
        # Ensure proxy image exists (rebuilds if pruned by GC or missing).
        self._ensure_proxy_image()

        # Tear down stale resources from a previous attempt (idempotent).
        self.stop_proxy(context_id)

        network_name = f"{self._context_network_prefix}{context_id}"
        container_name = f"{self._context_proxy_prefix}{context_id}"

        # Force-remove stale container and network by name.  If a
        # previous execution failed mid-way (e.g. ENOSPC) and
        # stop_proxy() couldn't remove the network (e.g. because a
        # workload container was still connected), the resources are
        # orphaned.  stop_proxy() above only cleans resources tracked
        # in _active_proxies, which will be empty on retry.  This
        # ensures we always start from a clean slate.
        self._remove_container(container_name)
        self._remove_network(network_name)

        logger.info(
            "Starting proxy for context %s (network=%s, container=%s)",
            context_id,
            network_name,
            container_name,
        )

        # Allocate subnet and create internal network with route to proxy.
        # Retries on subnet conflicts caused by other processes (e.g. another
        # airut instance sharing the same host).
        proxy_ip, subnet_octet = self._allocate_subnet_and_create_network(
            network_name
        )

        # Touch network log file if path provided
        if network_log_path is not None:
            self._create_network_log(context_id, network_log_path)

        try:
            # Write allowlist to temp file
            allowlist_path = self._write_temp_file(
                context_id,
                allowlist_json,
                "allowlist",
                self._allowlist_tmpfiles,
            )
            # Write replacement map to temp file
            replacement_path = self._write_temp_file(
                context_id,
                replacements_json,
                "replacements",
                self._replacement_tmpfiles,
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
            # Clean up network, container, subnet, and temp files on failure
            self._remove_container(container_name)
            self._remove_network(network_name)
            self._release_subnet(subnet_octet)
            self._cleanup_temp_file(context_id, self._allowlist_tmpfiles)
            self._cleanup_temp_file(context_id, self._replacement_tmpfiles)
            self._cleanup_network_log(context_id)
            raise

        proxy = _ContextProxy(
            network_name=network_name,
            proxy_container_name=container_name,
            proxy_ip=proxy_ip,
            subnet_octet=subnet_octet,
        )
        with self._lock:
            self._active_proxies[context_id] = proxy
        logger.info("Proxy started for context %s", context_id)
        return proxy

    def stop_proxy(self, context_id: str) -> None:
        """Stop proxy container and remove internal network for a context.

        Safe to call even if the proxy was never started or already
        stopped.

        Args:
            context_id: Execution context identifier.
        """
        with self._lock:
            proxy = self._active_proxies.pop(context_id, None)
        if proxy is None:
            logger.debug("No active proxy for context %s", context_id)
            return

        logger.info("Stopping proxy for context %s", context_id)
        self._remove_container(proxy.proxy_container_name)
        self._remove_network(proxy.network_name)
        self._release_subnet(proxy.subnet_octet)
        self._cleanup_temp_file(context_id, self._allowlist_tmpfiles)
        self._cleanup_temp_file(context_id, self._replacement_tmpfiles)
        # Note: we don't delete the network log file - it stays for
        # later inspection and is cleaned up with conversation pruning
        self._network_log_files.pop(context_id, None)
        logger.info("Proxy stopped for context %s", context_id)

    # ------------------------------------------------------------------
    # Subnet allocation
    # ------------------------------------------------------------------

    def _allocate_subnet(self) -> tuple[str, str, int]:
        """Allocate a /24 subnet and proxy IP for a new context network.

        Scans from ``_next_subnet_octet`` forward (with wraparound),
        skipping octets that are currently in use. Raises ``ProxyError``
        if all 254 octets are exhausted.

        Returns:
            Tuple of (subnet_cidr, proxy_ip, octet).

        Raises:
            ProxyError: If all 254 subnets are in use.
        """
        with self._lock:
            octet = self._next_subnet_octet
            for _ in range(254):
                if octet not in self._active_octets:
                    self._active_octets.add(octet)
                    self._next_subnet_octet = (octet % 254) + 1
                    break
                octet = (octet % 254) + 1
            else:
                raise ProxyError(
                    "All 254 subnets are in use; cannot allocate a new "
                    "context network"
                )
        subnet = f"{_SUBNET_PREFIX}.{octet}.0{_SUBNET_MASK}"
        proxy_ip = f"{_SUBNET_PREFIX}.{octet}.{_PROXY_HOST_OCTET}"
        return subnet, proxy_ip, octet

    def _release_subnet(self, octet: int) -> None:
        """Release a previously allocated subnet octet.

        Args:
            octet: Third octet of the /24 subnet to release.
        """
        with self._lock:
            self._active_octets.discard(octet)

    def _allocate_subnet_and_create_network(
        self, network_name: str
    ) -> tuple[str, int]:
        """Allocate a subnet and create the internal network.

        Retries automatically when a subnet is already in use on the host
        (e.g. held by another airut process). On conflict the octet is
        released so future calls can retry it (the external holder may
        have finished). Within a single call the allocator's advancing
        counter ensures the same octet is not retried.

        Args:
            network_name: Name for the internal network.

        Returns:
            Tuple of (proxy_ip, octet).

        Raises:
            ProxyError: If all 254 subnets are exhausted or network
                creation fails for a non-conflict reason.
        """
        for _ in range(254):
            try:
                subnet, proxy_ip, octet = self._allocate_subnet()
            except ProxyError:
                # All 254 exhausted in-memory.
                break

            try:
                self._create_internal_network(
                    network_name, subnet=subnet, proxy_ip=proxy_ip
                )
                return proxy_ip, octet
            except ProxyError as exc:
                error_msg = str(exc).lower()
                if "subnet" in error_msg and "already" in error_msg:
                    # Subnet held by another process -- release so
                    # future calls can retry (holder may have finished).
                    # The advancing counter prevents re-trying within
                    # this loop.
                    self._release_subnet(octet)
                    logger.info(
                        "Subnet %s in use externally, trying next", subnet
                    )
                    continue
                # Non-conflict error: release octet and propagate.
                self._release_subnet(octet)
                raise

        raise ProxyError(
            "All 254 subnets are in use or already claimed on the host; "
            "cannot allocate a new context network"
        )

    # ------------------------------------------------------------------
    # Image and CA cert
    # ------------------------------------------------------------------

    def _ensure_proxy_image(self) -> None:
        """Build or reuse proxy image via ImageCache."""
        spec = self._build_proxy_spec()
        self._proxy_image_tag = self._image_cache.ensure(spec)

    def _build_proxy_spec(self) -> ImageBuildSpec:
        """Construct ImageBuildSpec for the proxy image.

        Raises:
            ProxyError: If proxy Dockerfile is missing.
        """
        return build_proxy_spec(self._proxy_dir)

    def _ensure_ca_cert(self) -> Path:
        """Ensure mitmproxy CA certificate exists.

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

        assert self._proxy_image_tag is not None
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
                self._proxy_image_tag,
                "-c",
                f"mitmdump --set confdir={container_confdir} "
                "--listen-port 0 & sleep 3; kill $!",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            for _ in range(20):
                if ca_cert_path.exists():
                    break
                time.sleep(0.5)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if not ca_cert_path.exists():
            raise ProxyError(
                f"Failed to generate CA certificate at {ca_cert_path}"
            )

        logger.info("CA certificate generated: %s", ca_cert_path)
        return ca_cert_path

    # ------------------------------------------------------------------
    # Temp file operations
    # ------------------------------------------------------------------

    def _write_temp_file(
        self,
        context_id: str,
        data: bytes,
        label: str,
        tracking_dict: dict[str, Path],
    ) -> Path:
        """Write data to a temp file and track it for cleanup.

        Args:
            context_id: Execution context identifier.
            data: File contents.
            label: Label for the temp file prefix.
            tracking_dict: Dict to track the file path for cleanup.

        Returns:
            Path to the temporary file.
        """
        fd, path = tempfile.mkstemp(suffix=".json", prefix=f"airut-{label}-")
        with open(fd, "wb") as f:
            f.write(data)

        tmppath = Path(path)
        tracking_dict[context_id] = tmppath
        logger.debug("Wrote %s for context %s: %s", label, context_id, tmppath)
        return tmppath

    @staticmethod
    def _cleanup_temp_file(
        context_id: str, tracking_dict: dict[str, Path]
    ) -> None:
        """Remove a tracked temp file."""
        tmppath = tracking_dict.pop(context_id, None)
        if tmppath is not None:
            tmppath.unlink(missing_ok=True)

    def _create_network_log(
        self, context_id: str, network_log_path: Path
    ) -> None:
        """Touch the network log file and track it.

        Args:
            context_id: Execution context identifier (for tracking).
            network_log_path: File path for the network activity log.
        """
        # Create empty file (proxy addon will append to it)
        network_log_path.touch(exist_ok=True)
        self._network_log_files[context_id] = network_log_path
        logger.debug(
            "Created network log for context %s: %s",
            context_id,
            network_log_path,
        )

    def _cleanup_network_log(self, context_id: str) -> None:
        """Remove tracking for network log file (but keep the file)."""
        self._network_log_files.pop(context_id, None)

    # ------------------------------------------------------------------
    # Container operations
    # ------------------------------------------------------------------

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
            f"{allowlist_path}:/network-allowlist.json:ro",
        ]

        # Mount replacement map if provided
        if replacement_path is not None:
            cmd.extend(["-v", f"{replacement_path}:/replacements.json:ro"])

        # Mount network log file if provided
        if network_log_path is not None:
            cmd.extend(["-v", f"{network_log_path}:/network-sandbox.log:rw"])

        assert self._proxy_image_tag is not None
        cmd.append(self._proxy_image_tag)

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
        """Force-remove a container (idempotent)."""
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
        """Create a per-context internal network with route to proxy.

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
        """Force-remove a network (idempotent)."""
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
        """Remove orphaned proxy containers and context networks."""
        # Clean orphaned containers
        try:
            result = subprocess.run(
                [
                    self._cmd,
                    "ps",
                    "-a",
                    "--filter",
                    f"name={self._context_proxy_prefix}",
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
                    f"name={self._context_network_prefix}",
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
                    logger.info("Removing orphaned context network: %s", name)
                    self._remove_network(name)
        except subprocess.CalledProcessError:
            logger.debug("Failed to list orphaned networks")
