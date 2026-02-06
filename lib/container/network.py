# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network sandbox configuration for Claude Code containers.

Provides the Podman command-line arguments needed to route container traffic
through the network sandbox (per-task mitmproxy proxy).  When the sandbox is
disabled (break-glass), returns an empty list so containers get unrestricted
access.

The transparent proxy architecture works by:
1. DNS: Client's ``--dns`` points to the proxy IP, which runs a DNS
   responder returning the proxy IP for allowed domains (NXDOMAIN for blocked).
2. Routing: The internal network's ``--route`` flag injects a default
   route to the proxy IP, so all traffic reaches mitmproxy.
3. TLS: mitmproxy in ``regular`` mode terminates TLS using SNI to
   determine the real upstream host. The container trusts the mitmproxy CA.

No ``HTTP_PROXY``/``HTTPS_PROXY`` env vars needed — fully transparent.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lib.container.proxy import get_ca_cert_path


if TYPE_CHECKING:
    from lib.container.proxy import TaskProxy


logger = logging.getLogger(__name__)

CA_CONTAINER_PATH = "/usr/local/share/ca-certificates/mitmproxy-ca.crt"


def get_network_args(task_proxy: TaskProxy | None) -> list[str]:
    """Get Podman arguments for network sandbox enforcement.

    When a ``TaskProxy`` is provided, returns arguments to:
    - Attach the container to the task's internal network
    - Set ``--dns`` to the proxy IP (DNS responder)
    - Mount and trust the mitmproxy CA certificate

    When ``task_proxy`` is None (sandbox disabled or no proxy), returns
    an empty list for unrestricted network access.

    Args:
        task_proxy: Per-task proxy details, or None to skip.

    Returns:
        List of Podman command-line arguments.

    Raises:
        RuntimeError: If proxy infrastructure is not set up (CA certificate
            missing). Fails secure — containers must not run without network
            restrictions when a proxy is expected.
    """
    if task_proxy is None:
        logger.info("No task proxy — unrestricted network access")
        return []

    ca_cert_path = get_ca_cert_path()

    args: list[str] = []

    # Attach to per-task internal network
    args.extend(["--network", task_proxy.network_name])

    # Point DNS to proxy (runs dns_responder.py)
    args.extend(["--dns", task_proxy.proxy_ip])

    # Mount CA certificate
    args.extend(["-v", f"{ca_cert_path}:{CA_CONTAINER_PATH}:ro"])

    # Trust CA in all common TLS stacks
    args.extend(["-e", f"NODE_EXTRA_CA_CERTS={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"REQUESTS_CA_BUNDLE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"SSL_CERT_FILE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"CURL_CA_BUNDLE={CA_CONTAINER_PATH}"])

    logger.info(
        "Network sandbox enabled: proxy_ip=%s, network=%s",
        task_proxy.proxy_ip,
        task_proxy.network_name,
    )
    return args
