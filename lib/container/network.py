# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network sandbox configuration for Claude Code containers.

Provides the Podman command-line arguments needed to route container traffic
through the network sandbox (per-task mitmproxy proxy). When the sandbox is
disabled (break-glass), returns an empty list so containers get unrestricted
access.

Each task gets its own proxy container on its own internal network. The
proxy hostname is resolved via Podman's built-in DNS (aardvark-dns).
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
    - Set HTTP(S)_PROXY environment variables pointing to the proxy container
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

    proxy_url = f"http://{task_proxy.proxy_host}:{task_proxy.proxy_port}"

    args: list[str] = []

    # Attach to per-task internal network
    args.extend(["--network", task_proxy.network_name])

    # Proxy environment variables
    args.extend(["-e", f"HTTP_PROXY={proxy_url}"])
    args.extend(["-e", f"HTTPS_PROXY={proxy_url}"])

    # Mount CA certificate
    args.extend(["-v", f"{ca_cert_path}:{CA_CONTAINER_PATH}:ro"])

    # Trust CA in all common TLS stacks
    args.extend(["-e", f"NODE_EXTRA_CA_CERTS={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"REQUESTS_CA_BUNDLE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"SSL_CERT_FILE={CA_CONTAINER_PATH}"])
    args.extend(["-e", f"CURL_CA_BUNDLE={CA_CONTAINER_PATH}"])

    # Opt tools into using the proxy that don't honor HTTP(S)_PROXY
    args.extend(["-e", "ELECTRON_GET_USE_PROXY=1"])

    logger.info(
        "Network sandbox enabled: proxy=%s, network=%s",
        proxy_url,
        task_proxy.network_name,
    )
    return args
