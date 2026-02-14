# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network sandbox configuration for container execution.

Provides the Podman command-line arguments needed to route container traffic
through the network sandbox (per-task mitmproxy proxy).
"""

from __future__ import annotations

import logging
from pathlib import Path

from lib.sandbox._proxy import CA_CERT_FILENAME, MITMPROXY_CONFDIR


logger = logging.getLogger(__name__)

CA_CONTAINER_PATH = "/usr/local/share/ca-certificates/mitmproxy-ca.crt"


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
            "Sandbox.startup() must be called first."
        )
    return path


def get_network_args(network_name: str, proxy_ip: str) -> list[str]:
    """Get Podman arguments for network sandbox enforcement.

    Returns arguments to:
    - Attach the container to the task's internal network
    - Set ``--dns`` to the proxy IP (DNS responder)
    - Mount and trust the mitmproxy CA certificate

    Args:
        network_name: Per-task internal network name.
        proxy_ip: Proxy IP address on the internal network.

    Returns:
        List of Podman command-line arguments.

    Raises:
        RuntimeError: If proxy infrastructure is not set up (CA cert missing).
    """
    ca_cert_path = get_ca_cert_path()

    args: list[str] = []

    # Attach to per-task internal network
    args.extend(["--network", network_name])

    # Point DNS to proxy (runs dns_responder.py)
    args.extend(["--dns", proxy_ip])

    # Mount CA certificate
    args.extend(["-v", f"{ca_cert_path}:{CA_CONTAINER_PATH}:ro"])

    # Trust CA in all common TLS stacks
    args.extend(["-e", f"NODE_EXTRA_CA_CERTS={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"REQUESTS_CA_BUNDLE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"SSL_CERT_FILE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"CURL_CA_BUNDLE={CA_CONTAINER_PATH}"])

    logger.info(
        "Network sandbox enabled: proxy_ip=%s, network=%s",
        proxy_ip,
        network_name,
    )
    return args
